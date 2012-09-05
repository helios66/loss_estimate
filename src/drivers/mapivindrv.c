#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <netinet/in.h>
#include <dirent.h>
#include <time.h>
#include "mapi.h"
#include "mapidrv.h"
#include "mapidlib.h"
#include "printfstring.h"

#include "mapi_errors.h"
#include "mapidevices.h"
#include "flist.h"
#include "debug.h"

#define BUFSIZE 32768

#define NIC_PKTCAP_LEN 1514

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

static void mapidrv_proc_loop(void *);

typedef struct vin_instance {
  pthread_t th_proc;
  char *name;
  int id;
  char *trace_dir;
  int listeners;
  //mapi_offline_device_status_t *offline_status;
  mapid_hw_info_t hwinfo;
  mapidlib_instance_t mapidlib;
} vin_instance_t;

static flist_t *devlist;

/* for mapidlib errorcode */
int 
mapidrv_get_errno(int devid,int fd)
{
  vin_instance_t *i=flist_get(devlist,devid);
  return mapid_get_errno(&i->mapidlib,fd);
}

int
mapidrv_apply_function (int devid,int fd, int flags, char* function, mapiFunctArg *fargs)
{
  vin_instance_t *i=flist_get(devlist,devid);
  return mapid_apply_function(&i->mapidlib,fd, function, fargs, flags);
}

int dir_filter(const struct dirent *a) {
	return (a->d_name[0] == '.')?0:1;
}

int mapidrv_add_device(const char *devname, MAPI_UNUSED int file,int devid, global_function_list_t *gflist, void *trace_dir)
{
	if (trace_dir == NULL) {
		DEBUG_CMD(Debug_Message("ERROR: mapivindrv - null trace directory specified"));
		return -1;
	}

  vin_instance_t *i=malloc(sizeof(vin_instance_t));
  
  i->name=strdup(devname);
  i->id=devid;
  i->trace_dir=trace_dir;
  i->listeners=0;
  i->th_proc=0;
  i->hwinfo.offline=0;
  i->hwinfo.gflist=gflist;
  i->hwinfo.pkt_drop=0;

  DEBUG_CMD(Debug_Message("Added device %d: %s", devid, devname));

  flist_append(devlist,devid,i);
#ifdef WITH_AUTHENTICATION
  mapid_init(&i->mapidlib, &i->hwinfo);
#else
  mapid_init(&i->mapidlib);
#endif
  return 0;
}

int mapidrv_delete_device(int devid)
{
  vin_instance_t *i=flist_remove(devlist,devid);
  DEBUG_CMD(Debug_Message("---deleting device %d", devid));

  if (i!=NULL) {
	  mapid_destroy(&i->mapidlib);
	  DEBUG_CMD(Debug_Message(" %s %s", i->name, i->trace_dir));
	  free(i->name);
	  free(i->trace_dir);
	  free(i);
  }

  if (devlist->size == 0) {
	  mapid_destroy(NULL);
  }

  return 0;
}


static unsigned 
process_pkts(void *buf,unsigned len, vin_instance_t *i,MAPI_UNUSED int devid, int last)
{
  unsigned c = 0;
  int rlen = 0;
  struct pcap_pkthdr *rec;
  unsigned char *packet;
  mapid_pkthdr_t mhdr;

 rec = (struct pcap_pkthdr *) buf;
 rlen = rec->caplen+sizeof(struct pcap_pkthdr);

  while (c + rlen <= len) 
    {
      char *p = buf;
      buf = p + rlen;
      c += rlen;
      mhdr.caplen = rec->caplen;
      mhdr.ifindex = 0;
      mhdr.wlen = rec->len;
 
      mhdr.ts = (((unsigned long long)rec->ts.tv_sec)<<32)+(((rec->ts.tv_usec << 12) + (rec->ts.tv_usec<<8) - ((rec->ts.tv_usec*1825)>>5)) & 0xffffffff);
      
      // increase counter for packets seen so far
      i->hwinfo.pkts++;      
      
      packet=(unsigned char*)rec+(sizeof(struct pcap_pkthdr));

      if(last<BUFSIZE && c+rlen>len)
		i->hwinfo.offline=3;

      mapid_process_pkt(&i->mapidlib,(unsigned char*)rec,packet,&mhdr); 
      
      rec = (struct pcap_pkthdr *) buf;
      rlen = rec->caplen+sizeof(struct pcap_pkthdr);
    }

  return len - c;

}

static int process_dir(vin_instance_t *i, int devid, char *trace_dir) {
  struct dirent **dlist;
  int file_num, left=0, c, file, j;
  struct pcap_file_header head;
  char buf[BUFSIZE], *b=buf, *fname;

  file_num = scandir(trace_dir, &dlist, dir_filter, alphasort);

  DEBUG_CMD(Debug_Message("---processing directory '%s' (%d files)", trace_dir, file_num));
  
  if (file_num == -1) {
	DEBUG_CMD(Debug_Message("ERROR: in mapivindrv - scandir return -1"));
	return -1;
  }

  for (j=0; j < file_num; j++) {
	fname = printf_string("%s/%s", trace_dir, dlist[j]->d_name);
	if ((file=open(fname, O_LARGEFILE)) == -1) {
		DEBUG_CMD(Debug_Message("ERROR: in mapivindrv - error opening file %s", dlist[j]->d_name));
		perror("open");
		return -1;
	}
	
	DEBUG_CMD(Debug_Message("--- reading file %s", fname));
	//usleep(1000000);

  	c=read(file,&head,sizeof(struct pcap_file_header));
  	c=read(file,b,BUFSIZE);

  	while(c>0) {
    	left=process_pkts(buf,c+left,i,devid,c);
		pthread_yield();
		//nanosleep(&nap, NULL);
    	//Copy last bytes to beginning of buffer
    	memcpy(buf,b+c-left,left);
    	b=buf+left;
    	c=read(file,b,BUFSIZE-left);
  	}
	close(file);
	free(fname);
  }
  return 0;
}

static void
mapidrv_proc_loop(void *arg)
{
  int devid = *(int *)arg;
  int err;

  vin_instance_t *i=flist_get(devlist,devid);

  if(i==NULL) {
	DEBUG_CMD(Debug_Message("ERROR: MAPIDRV_PROC_LOOP - vin instance with id %d not in list", devid));
	return;
  }

  if ((err=pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL)) != 0) {
     DEBUG_CMD(Debug_Message("ERROR: pthread_setcanceltype failed (%s)", strerror(err)));
     return;
  }
  
  if ((err=pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) != 0) {
     DEBUG_CMD(Debug_Message("ERROR: pthread_setcancelstate (%s) failed", strerror(err)));
     return;
  }

  DEBUG_CMD(Debug_Message("--- entering proc loop"));

  while (1) {
	  if (process_dir(i, devid, i->trace_dir) != 0)
		  break;
  }
 
  mapid_finished(&i->mapidlib);
  DEBUG_CMD(Debug_Message("Finished reading file, pkts %lld", i->hwinfo.pkts));
}


int
mapidrv_read_results (int devid,int fd, int fid, mapid_result_t** result)
{
  vin_instance_t *i=flist_get(devlist,devid);
  return mapid_read_results(&i->mapidlib,fd,fid,result);
}

mapid_funct_info_t* mapidrv_get_flow_functions(int devid,int fd)
{
  vin_instance_t *i=flist_get(devlist,devid);
  return mapid_get_flow_functions(&i->mapidlib,fd);
}

int mapidrv_get_flow_info(int devid,int fd,mapi_flow_info_t *info) {
  vin_instance_t *i=flist_get(devlist,devid);
  return mapid_get_flow_info(&i->mapidlib,fd,info);
}

int
mapidrv_create_offline_flow (MAPI_UNUSED int devid, MAPI_UNUSED int format,
	MAPI_UNUSED int fd, MAPI_UNUSED char **devtype)
{
	DEBUG_CMD(Debug_Message("ERROR: mapivindrv does not support offline flows"));
	return VINDRV_OFF_ERR;
}

int
mapidrv_create_flow (int devid, int fd, char **devtype)
{
  vin_instance_t *i=flist_get(devlist,devid);
  *devtype=MAPI_DEVICE_VIN;

  i->listeners++;
  i->hwinfo.link_type=DLT_EN10MB;
  i->hwinfo.cap_length=1500;
  i->hwinfo.devtype=MAPI_DEVICE_VIN;
  i->hwinfo.devid=i->id;
  i->hwinfo.pkts=0;

  DEBUG_CMD(Debug_Message("---Created flow %d for dev %s", fd, i->name));

  return mapid_add_flow(&i->mapidlib,fd,&i->hwinfo,NULL);
}

int
mapidrv_connect (int devid,int fd)
{
  vin_instance_t *i=flist_get(devlist,devid);

  if (i->th_proc == 0) {
  	//Start processing thread
  	if (pthread_create(&i->th_proc, NULL, (void *) mapidrv_proc_loop, (void *) &(i->id)) != 0) {
   		DEBUG_CMD(Debug_Message("ERROR: pthread_create failed"));
	    	return VINDRV_PTHR_ERR;
  	}
	DEBUG_CMD(Debug_Message("---connect - created thread"));
  }
  else{
	DEBUG_CMD(Debug_Message("---connect - thread was running"));
  }
  
  return mapid_connect(&i->mapidlib,fd);
}

int 
mapidrv_start_offline_device(MAPI_UNUSED int devid)
{
	DEBUG_CMD(Debug_Message("ERROR: mapivindrv does not support offline flows"));
	return VINDRV_OFF_ERR;
}


int
mapidrv_close_flow (int devid,int fd)
{
  int err;
  vin_instance_t *i=flist_get(devlist,devid);
  
  if(i==NULL)
  	return VINDRV_DEVID_NOT_FOUND;

  i->listeners--;

  if (i->listeners == 0) {
  	  if ((err=pthread_cancel(i->th_proc))!=0) {
        if (!(i->hwinfo.offline>2 && err==ESRCH)) {
          DEBUG_CMD(Debug_Message("WARNING: Could not cancel thread for devid %d (%s)", devid, strerror(err)));
        }
      }
      
      if ((err=pthread_join(i->th_proc,NULL))!=0) {
        if (!(i->hwinfo.offline==1 && err==ESRCH)) {
          DEBUG_CMD(Debug_Message("WARNING: Could not join thread for devid %d (%s)", devid, strerror(err)));
        }
      }
	  i->th_proc = 0;
	  DEBUG_CMD(Debug_Message("---closing flow -- stopping thread"));
  }
  else{
	  DEBUG_CMD(Debug_Message("---closing flow -- NOT stopping thread"));
  }

  return mapid_close_flow(&i->mapidlib,fd);
}

int 
mapidrv_load_library(MAPI_UNUSED int devid,char* lib)
{
  return mapid_load_library(lib);
}


__attribute__ ((constructor))
     void init ()
{
  devlist=malloc(sizeof(flist_t));
  flist_init(devlist);
  printf("VIN driver loaded [%s:%d]\n", __FILE__, __LINE__);
}

__attribute__ ((destructor))
     void fini ()
{
  free(devlist);
  printf("VIN driver unloaded [%s:%d]\n", __FILE__, __LINE__);
}

