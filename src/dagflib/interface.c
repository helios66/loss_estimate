#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <dagapi.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "mapi_errors.h"

#include "dagnew.h"
#include "dagapi.h"
#include "dagutil.h"
#include "dagdsm.h"
#include "dag_config.h"
#include "dag_component.h"

#include "mapidagdrv.h"

typedef struct interface_instance_type {
  int ifindex;
} interface_instance_t;

static int interface_instance(mapidflib_function_instance_t *instance,
			      MAPI_UNUSED int fd,
			   MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  mapiFunctArg* a=instance->args;
  int ifindex = getargint(&a);
  
  if(ifindex<0)
    return MFUNCT_INVALID_ARGUMENT;
  
  return 0;
}

static int interface_init(mapidflib_function_instance_t *instance,
			  MAPI_UNUSED int fd)
//Initializes the function
{
  interface_instance_t *i=malloc(sizeof(interface_instance_t)); 
  mapiFunctArg* fargs=instance->args;

  i->ifindex=getargint(&fargs);

  instance->internal_data=i;
  return 0;
}

static int interface_process(mapidflib_function_instance_t *instance,
			unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
  dag_record_t *rec=(dag_record_t*)dev_pkt;
  interface_instance_t *i=instance->internal_data;

   if(rec->flags.iface==i->ifindex)
    return 1;
   
  return 0;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "INTERFACE", //name
  "Filters packets from specific interfaces on an adapter", //descr
  "i", //argdescr
  MAPI_DEVICE_DAG, //devtype
  MAPIRES_NONE, //Method for returning results
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_AUTO,
  interface_instance, //instance
  interface_init, //init
  interface_process, //process
  NULL, //get_result,
  NULL, //reset
  NULL, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* interface_get_funct_info();

mapidflib_function_def_t* interface_get_funct_info() {
  return &finfo;
};

