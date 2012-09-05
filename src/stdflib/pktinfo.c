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
#include "mapi_errors.h"
#include "mapid.h"
#include "fhelp.h"
#include "pktinfo.h"

static int pktinfo_instance(mapidflib_function_instance_t *instance,
			    MAPI_UNUSED int fd,
			    MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  int type;
  mapiFunctArg* fargs;

  //Check argument and get pointer to other function instance
  fargs=instance->args;

  type = getargint(&fargs);

  if(type!=PKT_TS && type!=PKT_SIZE)
    return MFUNCT_INVALID_ARGUMENT_2;

  return 0;
};

static int pktinfo_process_size(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			mapid_pkthdr_t* pkt_head)  
{
  (*(unsigned long long*)instance->result.data)=(unsigned long long)pkt_head->wlen;
  return 1;
}

static int pktinfo_init(mapidflib_function_instance_t *instance,
			MAPI_UNUSED int fd)
{
  int type;
  mapiFunctArg* fargs;

  //Check argument and get pointer to other function instance
  fargs=instance->args;

  type = getargint(&fargs);

  if(type==PKT_SIZE)
    instance->def->process=pktinfo_process_size;
  else if(type!=PKT_TS)
    return MFUNCT_INVALID_ARGUMENT_2;

  return 0;
}

static int pktinfo_process_ts(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			mapid_pkthdr_t* pkt_head)  
{
  (*(unsigned long long*)instance->result.data)=(unsigned long long)pkt_head->ts;
  return 1;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "PKTINFO", //name
  "Returns information about a packet as unsigned long long",
  "i", //argdescr
  MAPI_DEVICE_ALL, //devoid
  MAPIRES_SHM, //Method for returning results
  sizeof(unsigned long long), //shm size
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_AUTO, //Optimization
  pktinfo_instance,
  pktinfo_init,
  pktinfo_process_ts,
  NULL, //get_result,
  NULL, //reset
  NULL, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* pktinfo_get_funct_info();

mapidflib_function_def_t* pktinfo_get_funct_info() {
  return &finfo;
};



