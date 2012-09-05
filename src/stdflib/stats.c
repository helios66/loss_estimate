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
#include "stats.h"

typedef struct stats_inst {
  mapidflib_function_instance_t *res_instance;
  unsigned long long ticks;
  unsigned long long last;
  int fd;
  int fid;
} stats_inst_t;

static int stats_instance(mapidflib_function_instance_t *instance,
			  MAPI_UNUSED int fd,
			  MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  int fid;
  int afd;
  mapiFunctArg* fargs;
  
  //Check argument and get pointer to other function instance
  fargs=instance->args;

  afd = getargint(&fargs);
  fid = getargint(&fargs);
  
  if(fhlp_get_function_instance(instance->hwinfo->gflist,afd,fid)==NULL)
    return MFUNCT_INVALID_ARGUMENT_1;
  
    
  return 0;
};

static int stats_reset(mapidflib_function_instance_t *instance) 
{
  stats_t *stats;
  stats=instance->result.data;
  
  stats->count=0;
  stats->sum=0;
  stats->sum2=0;
  stats->max=0;
  stats->min=0;
  return 0;
}

static int stats_cleanup(mapidflib_function_instance_t *instance) 
{
  free(instance->internal_data);
  return 0;
}

static int stats_process_periodical(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
  unsigned long long *res;
  stats_inst_t *i=instance->internal_data;
  stats_t *s=instance->result.data;

  if(i->last==0)
      i->last=pkt_head->ts;
    else if(pkt_head->ts-i->last>i->ticks) {
    //Get result from other function
    res=((mapidflib_result_t*)fhlp_get_res(i->res_instance))->data;
    
    //Calculate statistics
    if(s->max<*res) {
      s->max=*res;
    }
    if(s->min>*res || s->min==0) {
      s->min=*res;
    }
       
    s->count++;    
    s->sum+=*res;
    s->sum2+=((long double)*res*(long double)*res);
    
    if(i->res_instance->def->reset!=NULL)
      i->res_instance->def->reset(i->res_instance);

    i->last+=i->ticks;
  }
  return 1;
}

static int stats_init(mapidflib_function_instance_t *instance,
		      MAPI_UNUSED int flow_descr)
{
  int fid,fd;
  stats_inst_t *i;
  char *t;

  mapiFunctArg* fargs=instance->args;

  i=instance->internal_data=malloc(sizeof(stats_inst_t));
  fd=getargint(&fargs);
  fid=getargint(&fargs);
  t=getargstr(&fargs);
  i->ticks=fhlp_str2ull(t);
  i->last=0;
  if((i->res_instance=fhlp_get_function_instance(instance->hwinfo->gflist,fd,fid))==NULL) {
    return MFUNCT_INVALID_ARGUMENT;
  }
 
  if(i->ticks!=0 && i->ticks!=1)
    instance->def->process=stats_process_periodical;
 
  return 0;
}


static int stats_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
  unsigned long long *res;
  stats_inst_t *i=instance->internal_data;
  stats_t *s=instance->result.data;
 
  if(i->ticks==1) 
    i->ticks=0; //Skip first packet
  else {
    //Get result from other function
    res=((mapidflib_result_t*)fhlp_get_res(i->res_instance))->data;
    
    //Calculate statistics
    if(s->max<*res) {
      s->max=*res;
    }
    if(s->min>*res || s->min==0) {
      s->min=*res;
    }
       
    s->count++;    
    s->sum+=*res;
    s->sum2+=((long double)*res*(long double)*res);
  }
  return 1;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "STATS", //name
  "Returns statistical information about unsigned long long values from other functions\nParameters:\n int fd - flowdescriptor of resultfunction\n int fid - function ID for reading results\n char skip - if set to 1 then skip results from first packet\nReturn type: mapi_stats_t", //descr
  "rfs", //argdescr
  MAPI_DEVICE_ALL, //devoid
  MAPIRES_SHM, //Method for returning results
  sizeof(stats_t), //shm size
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  stats_instance, //instance
  stats_init, //init
  stats_process, //process
  NULL, //get_result,
  stats_reset, //reset
  stats_cleanup, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* stats_get_funct_info();

mapidflib_function_def_t* stats_get_funct_info() {
  return &finfo;
};



