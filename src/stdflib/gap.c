#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"

static int gap_init(mapidflib_function_instance_t *instance,
		    MAPI_UNUSED int fd)
{
  unsigned long long *l;

  instance->internal_data=malloc(sizeof(unsigned long long));
  l=instance->internal_data;
  *l=0;
  return 0;
}

static int gap_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			mapid_pkthdr_t* pkt_head)  
{
  unsigned long long *gap,*old;
  old=instance->internal_data;
  gap=instance->result.data;
  
  if(*old!=0)
    *gap=pkt_head->ts-*old;
  
  *old=pkt_head->ts;

  return 1;
}

static int gap_cleanup(mapidflib_function_instance_t *instance)
{
  free(instance->internal_data);
  return 0;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "GAP", //name
  "Returns the gap between to consecuative packets\nReturn value: unsigned long long", //descr
  "", //argdescr
  MAPI_DEVICE_ALL, //devoid
  MAPIRES_SHM, //Method for returning results
  sizeof(unsigned long long), //shm size
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_AUTO, //Optimization
  NULL, //
  gap_init,
  gap_process,
  NULL, //get_result,
  NULL, //reset
  gap_cleanup, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* gap_get_funct_info();

mapidflib_function_def_t* gap_get_funct_info() {
  return &finfo;
};



