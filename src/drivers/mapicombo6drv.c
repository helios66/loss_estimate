#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/time.h>
#include "mapi.h"
#include "mapidrv.h"
#include "mapidlib.h"
#include "mapid.h"
#include "mapidevices.h"
#include "flist.h"
#include "debug.h"
#include "mapi_errors.h"

#include "libsze2.h"

typedef struct combo6_instance {
  int file;
  char *name;
  int id;
  pthread_attr_t th_attr;
  pthread_t th_proc;

  int combo6fd;
  struct szedata *sze;

  mapi_offline_device_status_t *offline_status;
  mapid_hw_info_t hwinfo;
  mapidlib_instance_t mapidlib;
} combo6_instance_t;

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

static flist_t *devlist;

/* for mapidlib errorcode */
int
mapidrv_get_errno(int devid, int fd)
{
  combo6_instance_t *i=flist_get(devlist,devid);
  return mapid_get_errno(&i->mapidlib, fd);
}

#ifdef WITH_AUTHENTICATION
int mapidrv_authenticate(int devid, int fd, char *vo)
{
  combo6_instance_t *i = flist_get(devlist, devid);
  return mapid_authenticate(&i->mapidlib, fd, vo);
}
#endif

int
mapidrv_connect (int devid, int fd)
{
  combo6_instance_t *i=flist_get(devlist,devid);
  return mapid_connect(&i->mapidlib, fd);
}

int
mapidrv_apply_function (int devid, int fd, int flags, char* function, mapiFunctArg *fargs)
{
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_apply_function; devid = %d; fd = %d; function = %s", devid, fd, function));

  combo6_instance_t *i=flist_get(devlist,devid);

  int _flags = flags;

  return mapid_apply_function(&i->mapidlib, fd, function, fargs, _flags);
}

int mapidrv_add_device(const char *devname, int file,int devid, global_function_list_t *gflist,void *olstatus)
{
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_add_device"));

  combo6_instance_t *i=malloc(sizeof(combo6_instance_t));

  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_add_device; devname: %s", devname));
  i->name=strdup(devname);
  i->id=devid;
  i->file=file;
  i->hwinfo.offline=0;
  i->combo6fd = -1;
  i->sze = NULL;
  i->hwinfo.devfd=i->combo6fd;
  i->hwinfo.gflist=gflist;
  i->hwinfo.pkt_drop=0;

  i->offline_status = olstatus;
  if(devid<0)
    i->hwinfo.offline = 1;

#ifdef DEBUG
  printf("Added device %d: %s\n",devid,devname);
#endif
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
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_delete_device"));

  combo6_instance_t *i=flist_remove(devlist,devid);

  if (i!=NULL) {
    int err=0;

    if (i->th_proc && pthread_equal(i->th_proc, pthread_self())==0) {
      DEBUG_CMD(Debug_Message("Calling thread != th_proc (%lu != %lu), cancelling", i->th_proc, pthread_self()));
      fflush(stdout);

      if ((err=pthread_cancel(i->th_proc))!=0) {
        if (!(i->hwinfo.offline==1 && err==ESRCH)) {
          DEBUG_CMD(Debug_Message("WARNING: Could not cancel thread for devid %d (%s)", devid, strerror(err)));
          fflush(stdout);
        }
      }
    }

    if (i->hwinfo.offline==0) {
      if(i->sze != NULL) {
        DEBUG_CMD(Debug_Message("szedata_close(%p)", i->sze));
        szedata_close(i->sze);
      }
    } else {
      if (i->file) {
        close(i->file);
        DEBUG_CMD(Debug_Message("Closed file"));
      }
    }

    mapid_destroy(&i->mapidlib);
    free(i->name);
    if(i->offline_status != NULL)
      *(i->offline_status) = DEVICE_DELETED;

    free(i);
  }

  return 0;
}

static void
mapidrv_proc_loop (void *arg)
{
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_proc_loop"));
  int devid = *(int *)arg;
  combo6_instance_t *i=flist_get(devlist,devid);
  int err;
  unsigned int rx = 0xff, tx = 0x00;

  unsigned char *packet;
  unsigned char *dev_pkt;
  unsigned char *link_pkt;
  unsigned int data_len;
  mapid_pkthdr_t mhdr;

  DEBUG_CMD(Debug_Message("combo6drv: subscribing: rx-0x%02hx tx-0x%02hx", rx, tx));
  err = szedata_subscribe(i->sze, &rx, &tx, SZE2_RX_POLL_CNT, SZE2_TX_POLL_CNT);
  if (err) {
    DEBUG_CMD(Debug_Message("combo6drv: ERROR subscring."));
  }
  else {
    DEBUG_CMD(Debug_Message("combo6drv: subscribed: rx-0x%02hx tx-0x%02hx", rx, tx));
  }

  err = szedata_start(i->sze);
  if (err) {
    DEBUG_CMD(Debug_Message("combo6drv: ERROR szedata_start()."));
  }
  else {
    DEBUG_CMD(Debug_Message("combo6drv: szedata_start()."));
  }

  struct timeval ts; // FIXME

  while (1)
    {

      packet = szedata_read_next(i->sze, &data_len);

      //unsigned int data_len;
      unsigned int hw_data_len;
      unsigned char *data;
      unsigned char *hw_data;


      if(packet) {
        //DEBUG_CMD(Debug_Message("combo6drv: packet..."));
        szedata_decode_packet(packet, &data, &hw_data, &data_len, &hw_data_len);
        dev_pkt = hw_data;
        link_pkt = data;
        mhdr.caplen=hw_data_len;
        mhdr.wlen=data_len;

        gettimeofday(&ts, NULL);
        mhdr.ts = (((unsigned long long)ts.tv_sec)<<32)+(((ts.tv_usec << 12) + (ts.tv_usec<<8) - ((ts.tv_usec*1825)>>5)) & 0xffffffff);

        mapid_process_pkt(&i->mapidlib,dev_pkt,link_pkt,&mhdr);
        i->hwinfo.pkts++;
      }

    }
}

int
mapidrv_read_results (int devid, int fd, int fid, mapid_result_t** result)
{
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_read_results"));
  combo6_instance_t *i=flist_get(devlist,devid);
  return mapid_read_results(&i->mapidlib,fd,fid,result);
}

mapid_funct_info_t* mapidrv_get_flow_functions(int devid,int fd)
{
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_get_flow_functions"));
  combo6_instance_t *i=flist_get(devlist,devid);
  return mapid_get_flow_functions(&i->mapidlib,fd);
}

int mapidrv_get_flow_info(int devid,int fd,mapi_flow_info_t *info) {
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_get_flow_info"));
  combo6_instance_t *i=flist_get(devlist,devid);
  return mapid_get_flow_info(&i->mapidlib,fd,info);
}

int
mapidrv_create_flow (int devid, int fd, char **devtype)
{
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_create_flow"));
  combo6_instance_t *i=flist_get(devlist,devid);

  if(devid < 0)
    {
      *devtype=MAPI_DEVICE_SCAMPI;
      i->hwinfo.offline=1;

      i->hwinfo.cap_length=1500;
      i->hwinfo.link_type=DLT_EN10MB;
      i->hwinfo.devtype=MAPI_DEVICE_SCAMPI;
      i->hwinfo.devid=i->id;
      i->hwinfo.pkts=0;

      DEBUG_CMD(Debug_Message("Reading from trace file: %s", i->name));

      return mapid_add_flow(&i->mapidlib,fd,&i->hwinfo,NULL);
    }

  i=flist_get(devlist,devid);

  i->hwinfo.offline=0;

  *devtype=MAPI_DEVICE_SCAMPI;

  //Open device if it is not already open
  if (i->sze == NULL)
    {
      if ((i->sze = szedata_open (i->name)) == NULL)   {
        fprintf (stderr, "szedata_open(%s): %s\n", i->name, strerror (errno));
        return COMBO6_OPEN_ERR;
      }
      fprintf (stderr, "szedata_open(%s): %p\n", i->name, i->sze);

      //This should be read from the hardware
      i->hwinfo.link_type=DLT_EN10MB;
      i->hwinfo.cap_length=1500;
      i->hwinfo.devtype=MAPI_DEVICE_SCAMPI;
      i->hwinfo.adapterinfo=&i->combo6fd;
      i->hwinfo.devid=i->id;
      i->hwinfo.pkts=0;

      //Start processing thread
      if (pthread_attr_init (&i->th_attr) != 0)
        {
          DEBUG_CMD(Debug_Message("ERROR: pthread_attr_init failed"));
          return COMBO6_PTHR_ERR;
        }
      if (pthread_create(&i->th_proc, &i->th_attr, (void *) mapidrv_proc_loop, (void *) &(i->id)) != 0)
        {
          DEBUG_CMD(Debug_Message("ERROR: pthread_create failed"));
          return COMBO6_PTHR_ERR;
        }
    }

  return mapid_add_flow(&i->mapidlib, fd,&i->hwinfo,NULL);
}

int mapidrv_load_library(int devid, char* lib)
{
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_load_library"));
  return mapid_load_library(lib);
}

int
mapidrv_close_flow (int devid, int fd)
{
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_close_flow"));
  combo6_instance_t *i=flist_get(devlist,devid);
  return mapid_close_flow (&i->mapidlib, fd);
}


__attribute__ ((constructor))
     void init ()
{
  // mapid_init();
  devlist=malloc(sizeof(flist_t));
  flist_init(devlist);
  printf ("Combo6 driver loaded\n");
}

__attribute__ ((destructor))
     void fini ()
{
  printf ("Combo6 driver unloaded\n");
}

void pktdrop(combo6_instance_t *i) {
  char buf[BUFSIZ];
  FILE *pipe;
  unsigned int hfe_x0_clas = 0;
  unsigned int hfe_x1_clas = 0;
  unsigned int crossbar2_trim_unit = 0;

  unsigned int failed = 0;

  if(pipe = popen("csbus 018C0008", "r")) {
    if(fgets(buf, BUFSIZ, pipe) != NULL) {
      if(!sscanf(buf, "%x", &hfe_x0_clas)) failed = 1;
    }
    else failed = 1;
    pclose(pipe);
  }
  else failed = 1;

  if(pipe = popen("csbus 018C000C", "r")) {
    if(fgets(buf, BUFSIZ, pipe) != NULL) {
      if(!sscanf(buf, "%x", &hfe_x1_clas)) failed = 1;;
    }
    else failed = 1;
    pclose(pipe);
  }
  else failed = 1;

  if(pipe = popen("csbus 018C8014", "r")) {
    if(fgets(buf, BUFSIZ, pipe) != NULL) {
      if(!sscanf(buf, "%x", &crossbar2_trim_unit)) failed = 1;
    }
    else failed = 1;
    pclose(pipe);
  }
  else failed = 1;

  if(!failed) {
    i->hwinfo.pkts = hfe_x0_clas + hfe_x1_clas;
    i->hwinfo.pkt_drop = hfe_x0_clas + hfe_x1_clas - crossbar2_trim_unit;
  }
  else {
    DEBUG_CMD(Debug_Message("combo6drv: pktdrop failed"));;
  }
}

int
mapidrv_stats (int devid, char **devtype, struct mapi_stat *stats)
{
  DEBUG_CMD(Debug_Message("combo6drv: mapidrv_stats"));

  combo6_instance_t *i=flist_get(devlist,devid);

  *devtype=MAPI_DEVICE_SCAMPI;

  if (i!=NULL)
  {
  pktdrop(i);
	stats->ps_recv=i->hwinfo.pkts + i->hwinfo.pkt_drop;
	stats->ps_drop=i->hwinfo.pkt_drop;
	stats->ps_ifdrop=0;
	return 0;
  }

  return MAPI_STATS_ERROR;
}

/* vim: set shiftwidth=2 tabstop=2 smarttab expandtab : */
