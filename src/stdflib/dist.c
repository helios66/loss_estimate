#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "debug.h"
#include "dist.h"
#include "mapi_errors.h"

int dist_old = 1;

typedef struct dist_internal {
  mapidflib_function_instance_t *res_instance;
  unsigned long long interval; //Interval size
  unsigned long long num;
  int fd;
  int fid;
} dist_internal_t;

static int dist_instance(mapidflib_function_instance_t *instance,
			 MAPI_UNUSED int fd,
			 MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  int afd,fid;
  unsigned long long min,max,interval;
  char *minstr, *maxstr, *intervalstr;
  mapiFunctArg* fargs=instance->args;

  afd=getargint(&fargs);
  fid=getargint(&fargs);
  minstr = getargstr(&fargs);
  maxstr = getargstr(&fargs);
  intervalstr = getargstr(&fargs);
  
  if(fhlp_get_function_instance(instance->hwinfo->gflist,afd,fid)==NULL)
    return MFUNCT_INVALID_ARGUMENT_1;

  if(minstr)
	min=fhlp_str2ull(minstr);
  else
	return MFUNCT_INVALID_ARGUMENT_3;
  if(maxstr)
	max=fhlp_str2ull(maxstr);
  else
	return MFUNCT_INVALID_ARGUMENT_4;
  if(interval)
	interval=fhlp_str2ull(intervalstr);
  else
	return MFUNCT_INVALID_ARGUMENT_5;

  if(min>max)
    return MFUNCT_INVALID_ARGUMENT;

  if(interval>(max-min))
    return MFUNCT_INVALID_ARGUMENT_4;
    
  instance->def->shm_size=sizeof(unsigned long long)*(ceil((double)(max-min)/(double)interval)+1)+sizeof(dist_t); 

  DEBUG_CMD(Debug_Message("SIZE: %d", instance->def->shm_size));

  return 0;
};

static int dist_reset(mapidflib_function_instance_t *instance) 
{
  unsigned long long *d;
  dist_t *dist=instance->result.data;
  unsigned long long c;

  d=dist->data;
  for(c=0;c<dist->intervals;c++)
    d[c]=0;
  return 0;
}

static int dist_init(mapidflib_function_instance_t *instance,
		     MAPI_UNUSED int flow_descr)
{
  mapiFunctArg* fargs=instance->args;
  int fid,fd;
  char *minstr, *maxstr, *intervalstr;
  dist_internal_t *i=instance->internal_data=malloc(sizeof(dist_internal_t));
  dist_t *dist=instance->result.data;
  
  fd=getargint(&fargs);
  fid=getargint(&fargs);
  minstr = getargstr(&fargs);
  maxstr = getargstr(&fargs);
  intervalstr = getargstr(&fargs);

  dist->min=fhlp_str2ull(minstr);
  dist->max=fhlp_str2ull(maxstr);
  i->interval=fhlp_str2ull(intervalstr);

  i->num=ceil(((double)(dist->max-dist->min)/(double)i->interval));
  i->res_instance=fhlp_get_function_instance(instance->hwinfo->gflist,fd,fid);
  dist->intervals=i->num;

  DEBUG_CMD(Debug_Message("Distribution: num=%lld", i->num));

  dist_reset(instance);
  return 0;
}

static int dist_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
  unsigned long long *res;
  dist_internal_t *i=instance->internal_data;
  dist_t *dist=instance->result.data;
  unsigned long long slot;
  
  //Get result from other function
  res=((mapidflib_result_t*)fhlp_get_res(i->res_instance))->data;

  if(res == NULL)
	  return -1;  

  if(*res<dist->min)
    slot=0;
  else if(*res>dist->max)
    slot=dist->intervals;
  else {
    slot=ceil((double)(*res-dist->min-1)/(double)i->interval);
    if(slot>i->num)
      slot=i->num;
  } 
  dist->data[slot]++;

  return 1;
}

static int dist_cleanup(mapidflib_function_instance_t *instance) {

	free(instance->internal_data);
	return 0;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "DIST", //name
  "Shows the distribution of results from other functions", //descr
  "rfsss", //argdescr
  MAPI_DEVICE_ALL, //devoid
  MAPIRES_SHM, //Method for returning results
  0, //shm size. Set by instance
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  dist_instance, //instance
  dist_init, //init
  dist_process, //process
  NULL, //get_result,
  dist_reset, //reset
  dist_cleanup, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* dist_get_funct_info();

mapidflib_function_def_t* dist_get_funct_info() {
  return &finfo;
};
