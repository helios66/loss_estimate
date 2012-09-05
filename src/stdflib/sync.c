#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapi_errors.h"
#include "mapid.h"
#include "fhelp.h"
#include "debug.h"

typedef struct sync_inst {
  mapid_flow_info_t **flow_info;
  int numfuncts;
} sync_inst_t;

static int sync_instance(mapidflib_function_instance_t *instance,
			     MAPI_UNUSED int flow_descr,
			     MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  char *fids,*s;
  int fd;
  char buf[DATA_SIZE],*cfids;
  char *t,*t2;

    mapiFunctArg* fargs=instance->args;

  if(!(fids = getargstr(&fargs)))
	return(MFUNCT_INVALID_ARGUMENT_2);

  //Loop through fids amd types and verify
  strncpy(buf,fids,DATA_SIZE);
  cfids=buf;
  while((s=strchr(cfids,','))!=NULL) {
    *s='\0';
    if((t2=strchr(t,','))==NULL)
      return MFUNCT_INVALID_ARGUMENT_1;
    *t2='\0';
    sscanf(cfids,"%d",&fd);
    if(flist_get(instance->hwinfo->gflist->fflist,fd)==NULL)
      return MFUNCT_INVALID_ARGUMENT_2;
    cfids=s+1;
  }
  sscanf(fids,"%d",&fd);
  if(flist_get(instance->hwinfo->gflist->fflist,fd)==NULL)
   return MFUNCT_INVALID_ARGUMENT_2; 

  return 0;
};

static int sync_init(mapidflib_function_instance_t *instance,
			 MAPI_UNUSED int flow_descr)
{
  sync_inst_t *i;
  char *fids,*s,*f;
  int fd,c;
  char buf[DATA_SIZE],*cfids;
  mapiFunctArg* fargs=instance->args;
  i=instance->internal_data=malloc(sizeof(sync_inst_t));  

  fids=getargstr(&fargs);

  //Count number of fids
  c=0;
  f=fids;
  while((s=strchr(f,','))!=NULL) {
    f=s+1;
    c++;
  }
  c++;
  i->flow_info=malloc(sizeof(mapid_flow_info_t*)*c);
  i->numfuncts=c;

  //Loop through fids and verify
  strncpy(buf,fids,DATA_SIZE);
  cfids=buf;
  c=0;
  while((s=strchr(cfids,','))!=NULL) {
    *s='\0';
    sscanf(cfids,"%d",&fd);
    i->flow_info[c]=flist_get(instance->hwinfo->gflist->fflist,fd);
    if(i->flow_info[c]==NULL)
      return MFUNCT_INVALID_ARGUMENT_2;
    c++;
    cfids=s+1;
  }
  sscanf(cfids,"%d",&fd);
  i->flow_info[c]=flist_get(instance->hwinfo->gflist->fflist,fd);

  return 0;
}

static int sync_process_true(MAPI_UNUSED mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
  return 1;
}

static int sync_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
  int c;
  sync_inst_t *i=instance->internal_data;

  for(c=0;c<i->numfuncts;c++) 
    if(i->flow_info[c]->status==FLOW_INIT)
      return 0;
  
  instance->def->process=sync_process_true;

  return 1;
}

static int sync_cleanup(mapidflib_function_instance_t *instance) 
{
  sync_inst_t *i=instance->internal_data;
  
  free(i->flow_info);
  free(i);
  return 0;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "SYNC", //name
  "Syncronizes multiple flows on the same device", //descr
  "s", //argdescr
  MAPI_DEVICE_ALL, //devoid
  MAPIRES_NONE, //Method for returning results
  0, //shm size
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  sync_instance, //instance
  sync_init, //init
  sync_process, //process
  NULL, //get_result,
  NULL, //reset
  sync_cleanup, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* sync_get_funct_info();

mapidflib_function_def_t* sync_get_funct_info() {
  return &finfo;
};
