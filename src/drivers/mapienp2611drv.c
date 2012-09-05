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

#define NIC_PKTCAP_LEN 1500

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

typedef struct enp2611_instance {
  pthread_attr_t th_attr;
  pthread_t th_proc;
  pcap_t *pcap;
  int eventset;
  void *buf;
  int file;
  char *name;
  int id;
  mapid_hw_info_t hwinfo;
  mapidlib_instance_t mapidlib;
} enp2611_instance_t;

static flist_t *devlist;

/* for mapidlib errorcode */
int 
mapidrv_get_errno(int devid,int fd)
{
  enp2611_instance_t *i=flist_get(devlist,devid);
  return mapid_get_errno(&i->mapidlib,fd);
}

#ifdef WITH_AUTHENTICATION
int mapidrv_authenticate(int devid, int fd, char *vo)
{
	enp2611_instance_t *i = flist_get(devlist, devid);
	return mapid_authenticate(&i->mapidlib, fd, vo);
}
#endif

int
mapidrv_apply_function (int devid,int fd, int flags, char* function, mapiFunctArg *fargs)
{
  enp2611_instance_t *i=flist_get(devlist,devid);
  return mapid_apply_function(&i->mapidlib,fd, function, fargs, flags);
}

int mapidrv_add_device(const char *devname, int file,int devid, global_function_list_t *gflist,void *olstatus)
{
  enp2611_instance_t *i=malloc(sizeof(enp2611_instance_t));
  i->name=strdup(devname);
  i->id=devid;
  i->pcap=NULL;
  i->file=file;
  i->th_proc=0;
  i->hwinfo.offline=0;
  i->hwinfo.gflist=gflist;
  i->hwinfo.pkt_drop=0;
  if(devid<0)
      return DRV_OFF_ERR;

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
  enp2611_instance_t *i=flist_remove(devlist,devid);
  
  if (i!=NULL) {
    int err=0;

      fflush(stdout);
      
      
         
    if (i->hwinfo.offline==0) {
      if (i->pcap != NULL) {
	//Modify: close connection with the device
	pcap_close(i->pcap);
        DEBUG_CMD(Debug_Message("Closed pcap handle"));
      }
    }

    mapid_destroy(&i->mapidlib);
    free(i->name);
    free(i);
  }

  if (devlist->size == 0) {
	  mapid_destroy(NULL);
  }

  return 0;
}

static void
mapidrv_proc_loop (void *arg)
{
  int devid = *(int *)arg;
  u_char *packet;
  struct pcap_pkthdr phdr;
  mapid_pkthdr_t mhdr;
  enp2611_instance_t *i=flist_get(devlist,devid);
  int err;

  if ((err=pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL)) != 0) {
     DEBUG_CMD(Debug_Message("ERROR: pthread_setcanceltype failed (%s)", strerror(err)));
     return;
  }
  
  if ((err=pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) != 0) {
     DEBUG_CMD(Debug_Message("ERROR: pthread_setcancelstate (%s) failed", strerror(err)));
     return;
  }

  while (1)
    {
      //Modify: get next packet from device
      while( (packet = (u_char *)pcap_next(i->pcap,&phdr)) == NULL );
      
      // Transform header
      //Modify: set the capture and wire lenght of the new packet
      mhdr.caplen = phdr.caplen;
      mhdr.wlen = phdr.len;

      //Modify: set the time stamp of the packet
	  mhdr.ts = (((unsigned long long)phdr.ts.tv_sec)<<32)+((((phdr.ts.tv_usec << 12) + (phdr.ts.tv_usec<<8) - ((phdr.ts.tv_usec*1825)>>5))) & 0xffffffff);    
      // increase counter for packets seen so far
      i->hwinfo.pkts++;
      
      // Process packet
      mapid_process_pkt(&i->mapidlib,packet,packet,&mhdr);
      
    }
 }

int
mapidrv_read_results (int devid,int fd, int fid, mapid_result_t** result)
{
  enp2611_instance_t *i=flist_get(devlist,devid);
  return mapid_read_results(&i->mapidlib,fd,fid,result);
}

mapid_funct_info_t* mapidrv_get_flow_functions(int devid,int fd)
{
  enp2611_instance_t *i=flist_get(devlist,devid);
  return mapid_get_flow_functions(&i->mapidlib,fd);
}

int mapidrv_get_flow_info(int devid,int fd,mapi_flow_info_t *info) {
  enp2611_instance_t *i=flist_get(devlist,devid);
  return mapid_get_flow_info(&i->mapidlib,fd,info);
}

int
mapidrv_create_offline_flow (int devid, int format,int fd,char **devtype)
{
  return DRV_OFF_ERR;
}

int
mapidrv_create_flow (int devid, int fd, char **devtype)
{
  enp2611_instance_t *i=flist_get(devlist,devid);
  char errbuf[PCAP_ERRBUF_SIZE];

  //i->hwinfo.offline=0;

  *devtype=MAPI_DEVICE_ENP2611;
  	
  //Open device if it is not already open
  if (i->pcap==NULL)
  {
    //Modify: initialize card
    if( (i->pcap = pcap_open_live(i->name,NIC_PKTCAP_LEN,1,0,errbuf)) == NULL )
      {
	DEBUG_CMD(Debug_Message("ERROR: pcap_open_live: %s", errbuf));
	return PCAP_OPEN_ERR;
      }
          
    //Modify: set correct link type (hard code to DLT_EN10MB?)
      i->hwinfo.link_type = pcap_datalink(i->pcap);
      i->hwinfo.cap_length = pcap_snapshot(i->pcap);
      i->hwinfo.devid=i->id;
      i->hwinfo.pkts=0;
      i->hwinfo.devtype=MAPI_DEVICE_ENP2611;

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
mapidrv_connect (int devid,int fd)
{
  enp2611_instance_t *i=flist_get(devlist,devid);
  int ret = mapid_connect(&i->mapidlib,fd);

  return ret;
}

int 
mapidrv_start_offline_device( int devid)
{
    return DRV_OFF_ERR;
}


int
mapidrv_close_flow (int devid,int fd)
{
  enp2611_instance_t *i=flist_get(devlist,devid);
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

