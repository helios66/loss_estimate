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
#include <pcap.h>
#include "mapi.h"
#include "mapidrv.h"
#include "mapidlib.h"

#include "mapi_errors.h"
#include "mapidevices.h"
#include "flist.h"
#include "debug.h"

#define ETHSTR     "eth"
#define LOSTR      "lo"

#ifdef USE_PAPI
#include <papi.h>
#define NUM_EVENTS 2
#define BUFSIZE 1048576*5 //5MB
#else
#define BUFSIZE 32768
#endif

#define NIC_PKTCAP_LEN 1514

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

typedef struct nic_instance {
  pthread_attr_t th_attr;
  pthread_t th_proc;
  pcap_t *pcap;
  int eventset;
  void *buf;
  int file;
  char *name;
  int id;
  mapi_offline_device_status_t *offline_status;
  mapid_hw_info_t hwinfo;
  mapidlib_instance_t mapidlib;
} nic_instance_t;

static flist_t *devlist;
/* for mapidlib errorcode */
int 
mapidrv_get_errno(int devid,int fd)
{
  nic_instance_t *i=flist_get(devlist,devid);
  return mapid_get_errno(&i->mapidlib,fd);
}

int
mapidrv_apply_function (int devid,int fd, int flags, char* function, mapiFunctArg *fargs)
{
  nic_instance_t *i=flist_get(devlist,devid);
  return mapid_apply_function(&i->mapidlib,fd, function, fargs, flags);
}

int mapidrv_add_device(const char *devname, int file,int devid, global_function_list_t *gflist,void *olstatus)
{
  nic_instance_t *i=malloc(sizeof(nic_instance_t));
  i->name=strdup(devname);
  i->id=devid;
  i->pcap=NULL;
  i->file=file;
  i->th_proc=0;
  i->hwinfo.offline=0;
  i->hwinfo.devfd=-1;
  i->hwinfo.gflist=gflist;
  i->hwinfo.pkt_drop=0;
  i->offline_status = olstatus;
  if(devid<0)
    i->hwinfo.offline=1;
  DEBUG_CMD(Debug_Message("Added device %d: %s", devid, devname));

  flist_append(devlist,devid,i);

  mapid_init(&i->mapidlib);

  return 0;
}

int mapidrv_delete_device(int devid)
{
  nic_instance_t *i=flist_remove(devlist,devid);
  
  if (i!=NULL) {
    int err=0;

      if(i->th_proc) {

      if ((err=pthread_cancel(i->th_proc))!=0) {
        if (!(i->hwinfo.offline>2 && err==ESRCH)) {
          DEBUG_CMD(Debug_Message("WARNING: Could not cancel thread for devid %d (%s)", devid, strerror(err)));
          fflush(stdout);
        }
      }
      
      if ((err=pthread_join(i->th_proc,NULL))!=0) {
        if (!(i->hwinfo.offline==1 && err==ESRCH)) {
          DEBUG_CMD(Debug_Message("WARNING: Could not join thread for devid %d (%s)", devid, strerror(err)));
          fflush(stdout);
        }
      }

      if ((err=pthread_attr_destroy(&i->th_attr))!=0){
	DEBUG_CMD(Debug_Message("WARNING: Could not destroy threads attribute object for devid %d (%s)", devid, strerror(err)));
      }
    }
   
    if (i->hwinfo.offline==0) {
      if (i->pcap != NULL) {
	pcap_close(i->pcap);
        DEBUG_CMD(Debug_Message("Closed pcap handle"));
      }
    } else {
      if (i->file) {
        close(i->file);
        DEBUG_CMD(Debug_Message("Closed file"));
      }
    }

    mapid_destroy(&i->mapidlib);
    free(i->name);
    if(i->offline_status!=NULL)
      *(i->offline_status) = DEVICE_DELETED;
    free(i);
  }

  if (devlist->size == 0) {
	  mapid_destroy(NULL);
  }

  return 0;
}

static unsigned 
process_pkts(void *buf,unsigned len, nic_instance_t *i,MAPI_UNUSED int devid, int last)
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
      
      //      if(c+sizeof(dag_record_t)>len-sizeof(dag_record_t)*2)
      //break;
      rec = (struct pcap_pkthdr *) buf;
      rlen = rec->caplen+sizeof(struct pcap_pkthdr);
    }

  //mapid_delete_flows(&i->mapidlib);

  return len - c;

}

static void
mapidrv_offline_proc_loop(void *arg)
{
  int devid = *(int *)arg;
  char buf[BUFSIZE];
  char *b=buf;
  int left=0,c;
  nic_instance_t *i=flist_get(devlist,devid);
  int err;

#ifdef USE_PAPI
  int Events[NUM_EVENTS] = {PAPI_TOT_INS, PAPI_TOT_CYC}; //See http://icl.cs.utk.edu/projects/papi/presets.html                  
  int num_hwcntrs = 0;
  int retval;
  unsigned long long pkts;
  char errstring[PAPI_MAX_STR_LEN];
  long_long values[NUM_EVENTS];

   if((retval = PAPI_library_init(PAPI_VER_CURRENT)) != PAPI_VER_CURRENT )
   {
      DEBUG_CMD(Debug_Message("ERROR: %d %s", retval, errstring));
      exit(1);
   }

   if ((num_hwcntrs = PAPI_num_counters()) < PAPI_OK)
     {
       DEBUG_CMD(Debug_Message("ERROR: There are no counters available"));
       exit(1);
   }
#endif

  if(i==NULL)
  {
	DEBUG_CMD(Debug_Message("ERROR: MAPIDRV_OFFLINE_PROC_LOOP - nic instance with id %d not in list", devid));
	return;
  }
  else
  	*(i->offline_status) = DEVICE_READING;

  if ((err=pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL)) != 0) {
     DEBUG_CMD(Debug_Message("ERROR: pthread_setcanceltype failed (%s)", strerror(err)));
     return;
  }
  
  if ((err=pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) != 0) {
     DEBUG_CMD(Debug_Message("ERROR: pthread_setcancelstate (%s) failed", strerror(err)));
     return;
  }

  c=read(i->file,b,BUFSIZE);

#ifdef USE_PAPI
  if ( (retval = PAPI_start_counters(Events, NUM_EVENTS)) != PAPI_OK) {
    DEBUG_CMD(Debug_Message("ERROR: %d %s", retval, errstring));
    exit(retval);
  }
#endif

  while(c>0) {    

#ifdef USE_PAPI
    pkts=i->hwinfo.pkts;     
#endif
 
    left=process_pkts(buf,c+left,i,devid,c);
 
#ifdef USE_PAPI
    pkts=i->hwinfo.pkts-pkts;      
    if ( (retval=PAPI_read_counters(values, NUM_EVENTS)) != PAPI_OK) {
      DEBUG_CMD(Debug_Message("ERROR: %d %s", retval, errstring));
      exit(retval);
    }
    DEBUG_CMD(Debug_Message("Total:\t\t%lld\t%lld", values[0], values[1]));
    DEBUG_CMD(Debug_Message("Per pkt:\t%.1lf\t%.1lf", (double)values[0]/pkts, (double)values[1]/pkts));
#endif

    //Copy last bytes to beginning of buffer
    memcpy(buf,b+c-left,left);
    b=buf+left;

    c=read(i->file,b,BUFSIZE-left);

#ifdef USE_PAPI
    if ( (retval=PAPI_accum_counters(values, NUM_EVENTS)) != PAPI_OK) {
      DEBUG_CMD(Debug_Message("ERROR: %d %s", retval, errstring));
      exit(retval);
    }
#endif

  }
  mapid_finished(&i->mapidlib);
  *(i->offline_status) = DEVICE_FINISHED;
  DEBUG_CMD(Debug_Message("Finished reading file, pkts %lld", i->hwinfo.pkts));
}

void
callback(u_char *user, const struct pcap_pkthdr *phdr,
                                   const u_char *bytes) {
	nic_instance_t *i = (nic_instance_t*)user;
	mapid_pkthdr_t mhdr;

	mhdr.caplen = phdr->caplen;
	mhdr.wlen = phdr->len;
	mhdr.ts = (((unsigned long long)phdr->ts.tv_sec)<<32)+((((phdr->ts.tv_usec << 12) + (phdr->ts.tv_usec<<8) - ((phdr->ts.tv_usec*1825)>>5))) & 0xffffffff);

	i->hwinfo.pkts++;

	mapid_process_pkt(&i->mapidlib,(unsigned char*)bytes,(unsigned char*)bytes,&mhdr);
}

static void
mapidrv_proc_loop (void *arg)
{
  int devid = *(int *)arg;
  nic_instance_t *i=flist_get(devlist,devid);
  int err;

  if ((err=pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL)) != 0) {
     DEBUG_CMD(Debug_Message("ERROR: pthread_setcanceltype failed (%s)", strerror(err)));
     return;
  }
  
  if ((err=pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) != 0) {
     DEBUG_CMD(Debug_Message("ERROR: pthread_setcancelstate (%s) failed", strerror(err)));
     return;
  }

  pcap_loop(i->pcap, -1, callback, (void*)i);
 }

int
mapidrv_read_results (int devid,int fd, int fid, mapid_result_t** result)
{
  nic_instance_t *i=flist_get(devlist,devid);
  return mapid_read_results(&i->mapidlib,fd,fid,result);
}

mapid_funct_info_t* mapidrv_get_flow_functions(int devid,int fd)
{
  nic_instance_t *i=flist_get(devlist,devid);
  return mapid_get_flow_functions(&i->mapidlib,fd);
}

int mapidrv_get_flow_info(int devid,int fd,mapi_flow_info_t *info) {
  nic_instance_t *i=flist_get(devlist,devid);
  return mapid_get_flow_info(&i->mapidlib,fd,info);
}

int
mapidrv_create_flow (int devid, int fd, char **devtype)
{
  nic_instance_t *i=flist_get(devlist,devid);
  char errbuf[PCAP_ERRBUF_SIZE];

  //i->hwinfo.offline=0;

  *devtype=MAPI_DEVICE_NIC;
  if(i->hwinfo.offline > 0)
  {
    //This should be read from the file
    i->hwinfo.link_type=DLT_EN10MB;
    i->hwinfo.cap_length=1500;
    i->hwinfo.devtype=MAPI_DEVICE_NIC;
    i->hwinfo.devid=i->id;
    i->hwinfo.pkts=0;

    DEBUG_CMD(Debug_Message("Reading from trace file: %s", i->name));

    return mapid_add_flow(&i->mapidlib,fd,&i->hwinfo,NULL);
  }
  	
  //Open device if it is not already open
  if (i->pcap==NULL)
  {
    if( (i->pcap = pcap_open_live(i->name,NIC_PKTCAP_LEN,1,0,errbuf)) == NULL )
      {
	DEBUG_CMD(Debug_Message("ERROR: pcap_open_live: %s", errbuf));
	return PCAP_OPEN_ERR;
      }
      
      i->hwinfo.devfd=pcap_fileno(i->pcap);
      i->hwinfo.link_type = pcap_datalink(i->pcap);
      i->hwinfo.cap_length = pcap_snapshot(i->pcap);
      i->hwinfo.devid=i->id;
      i->hwinfo.pkts=0;
      i->hwinfo.devtype=MAPI_DEVICE_NIC;

      //Start processing thread
      if (pthread_attr_init (&i->th_attr) != 0)
    	{
    	  DEBUG_CMD(Debug_Message("ERROR: pthread_attr_init failed"));
    	  return NICDRV_PTHR_ERR;
    	}
    
      if (pthread_create(&i->th_proc, &i->th_attr, (void *) mapidrv_proc_loop, (void *) &(i->id)) != 0)
    	{
    	  DEBUG_CMD(Debug_Message("ERROR: pthread_create failed"));
    	  return DAGDRV_PTHR_ERR;
    	}    
    }
  return   mapid_add_flow(&i->mapidlib,fd,&i->hwinfo,NULL);
}

int
mapidrv_stats (int devid, char **devtype, struct mapi_stat *stats)
{
  nic_instance_t *i=flist_get(devlist,devid);
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_stat p_stats;

  *devtype=MAPI_DEVICE_NIC;

  if (i->pcap!=NULL)
  {
    if( pcap_stats(i->pcap, &p_stats) != 0 )
      {
	DEBUG_CMD(Debug_Message("ERROR: pcap_stats: %s", errbuf));
	return MAPI_STATS_ERROR;
      }
    else 
      {
	stats->ps_recv=p_stats.ps_recv;
	stats->ps_drop=p_stats.ps_drop;
	stats->ps_ifdrop=p_stats.ps_ifdrop;
	return 0;
      }
  }
  return MAPI_STATS_ERROR;
}


int
mapidrv_connect (int devid,int fd)
{
  nic_instance_t *i=flist_get(devlist,devid);
  int ret = mapid_connect(&i->mapidlib,fd);
  if(i->hwinfo.offline==4) {
    if (pthread_attr_init (&i->th_attr) != 0)
      {
		DEBUG_CMD(Debug_Message("ERROR: pthread_attr_init failed"));
		return NICDRV_PTHR_ERR;
      }
    if (pthread_create(&i->th_proc, &i->th_attr, (void *) mapidrv_offline_proc_loop, (void *) &(i->id)) != 0)
      {
		DEBUG_CMD(Debug_Message("ERROR: pthread_create failed"));
		return NICDRV_PTHR_ERR;
      }    
  }
  return ret;
}

int 
mapidrv_start_offline_device( int devid)
{
  nic_instance_t *i = flist_get(devlist,devid);
  int c;
  struct pcap_file_header head;
  
  if(i->hwinfo.offline==1) {
    c=read(i->file,&head,sizeof(struct pcap_file_header));
    i->hwinfo.link_type=head.linktype;
    if (pthread_attr_init (&i->th_attr) != 0)
      {
		DEBUG_CMD(Debug_Message("ERROR: pthread_attr_init failed"));
		return NICDRV_PTHR_ERR;
      }
    if (pthread_create(&i->th_proc, &i->th_attr, (void *) mapidrv_offline_proc_loop, (void *) &(i->id)) != 0)
      {
		DEBUG_CMD(Debug_Message("ERROR: pthread_create failed"));
		return NICDRV_PTHR_ERR;
      }    
  }
  return 0;
}


int
mapidrv_close_flow (int devid,int fd)
{
  nic_instance_t *i=flist_get(devlist,devid);
  if(i==NULL)
  	return -1;

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
  printf("NIC driver loaded [%s:%d]\n", __FILE__, __LINE__);
}

__attribute__ ((destructor))
     void fini ()
{

  free(devlist);
  printf("NIC driver unloaded [%s:%d]\n", __FILE__, __LINE__);
}

