#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include "mapi_errors.h"
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"

static int <funct_name>_instance(mapidflib_function_instance_t *instance,
				 int fd,
				 mapidflib_flow_mod_t *flow_mod)
{
  return 0;
};

static int <funct_name>_init(mapidflib_function_instance_t *instance,
			     int fd)
{
  return 0;
}

static int <funct_name>_process(mapidflib_function_instance_t *instance,
			unsigned char* dev_pkt,
			unsigned char* link_pkt,
			mapid_pkthdr_t* pkt_head)  
{
  return 1;
}

static int <funct_name>_get_result(mapidflib_function_instance_t* instance,
				   mapidflib_result_t **res)
{
  return 0;
}

static int <funct_name>_reset(mapidflib_function_instance_t *instance) 
{
  return 0;
}

static int <funct_name>_cleanup(mapidflib_function_instance_t *instance) 
{
  return 0;
}

static int <funct_name>_client_init(mapidflib_function_instance_t *instance, 
				    void* data)
{
  return 0;
}

static int <funct_name>_client_read_result(mapidflib_function_instance_t* instance,
					   mapid_result_t *res)
{
  return 0;
}

static int <funct_name>_client_cleanup(mapidflib_function_instance_t* instance)
{
  return 0;
}

static mapidflib_function_def_t finfo={
  "",                              //libname (set at runtime)
  "<funct_name>",                  //name
  "<description>",                 //descr: multiline description
  "<argdescr>",                    //argdescr: letter describing arguments
  MAPI_DEVICE_ALL,                 //devtype
  MAPIRES_<SHM|IPC|FUNCT|NONE>,    //method for returning results
  0,                               //shm size
  0,                               //modifies_pkts
  0,                               //filters_pkts
  MAPIOPT_<NONE|AUTO|MANUAL>,      //global optimization method
  <funct_name>_instance,           //instance
  <funct_name>_init,               //init
  <funct_name>_process,            //process
  <funct_name>_get_result,         //get_result,
  <funct_name>_reset,              //reset
  <funct_name>_cleanup,            //cleanup
  <funct_name>_client_init,        //client_init
  <funct_name>_client_read_result, //client_read_result
  <funct_name>_client_cleanup      //client_cleanup
};

mapidflib_function_def_t* <funct_name>_get_funct_info() {
  return &finfo;
};

