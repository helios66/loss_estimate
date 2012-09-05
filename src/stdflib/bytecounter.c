#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"

static int bytec_process(mapidflib_function_instance_t *instance,
			 MAPI_UNUSED unsigned char* dev_pkt,
			 MAPI_UNUSED unsigned char* link_pkt,
			 mapid_pkthdr_t* pkt_head)
{
  unsigned long long *counter;
  counter=instance->result.data;
  (*counter)+=pkt_head->wlen;
  return 1;
}

static int bytec_reset(mapidflib_function_instance_t *instance) 
{
  unsigned long long *counter;
  counter = instance->result.data;
  *counter=0;
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "BYTE_COUNTER",
  "Counts number of bytes captured",
  "",
  MAPI_DEVICE_ALL,
  MAPIRES_SHM,
  sizeof(unsigned long long), //shm size
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  NULL, //instance
  NULL, //init
  bytec_process,
  NULL, //get_result
  bytec_reset,
  NULL, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* bytec_get_funct_info();
mapidflib_function_def_t* bytec_get_funct_info() {
  return &finfo;
};



