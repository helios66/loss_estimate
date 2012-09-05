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
#include "binop.h"

typedef struct binop_inst {
  mapidflib_function_instance_t *left,*right;
} binop_inst_t;

static int binop_init(mapidflib_function_instance_t *instance, 
		      MAPI_UNUSED int fd)
{
   int type;
   mapiFunctArg* fargs;

  //Check argument and get pointer to other function instance
  fargs=instance->args;
  type = getargint(&fargs);

  if(type!=BINOP_ADD && type!=BINOP_SUB)
    return MFUNCT_INVALID_ARGUMENT_1;

  return 0;
}

static int binop_process_add(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
	unsigned long long *res,*left,*right;	
	binop_inst_t *i = instance->internal_data;
	
	res=instance->result.data;
	left=((mapidflib_result_t*)fhlp_get_res(i->left))->data;
	right=((mapidflib_result_t*)fhlp_get_res(i->right))->data;

	if (left==NULL || right==NULL) { *res=-1; return -1;}
	*res=*left+*right;
	return 1;
}

static int binop_process_sub(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
	unsigned long long *res,*left,*right;	
	binop_inst_t *i=instance->internal_data;
	
	res=instance->result.data;	
	left=((mapidflib_result_t*)fhlp_get_res(i->left))->data;
	right=((mapidflib_result_t*)fhlp_get_res(i->right))->data;

	if (left==NULL || right==NULL) { *res=-1; return -1;}
	*res=*left-*right;
	return 1;
}

static int binop_instance(mapidflib_function_instance_t *instance,
			  MAPI_UNUSED int fd,
			  MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  int type, flow1, function1, flow2, function2;
  mapiFunctArg* fargs;
  binop_inst_t *i=instance->internal_data=malloc(sizeof(binop_inst_t));

  //Check argument and get pointer to other function instance
  fargs=instance->args;

  type = getargint(&fargs);
  flow1 = getargint(&fargs);
  function1 = getargint(&fargs);
  flow2 = getargint(&fargs);
  function2 = getargint(&fargs);
  
  i->left = fhlp_get_function_instance(instance->hwinfo->gflist, flow1, function1);
  i->right = fhlp_get_function_instance(instance->hwinfo->gflist, flow2, function2);

  if(i->left == NULL)
	  return MFUNCT_INVALID_ARGUMENT_2;
  
  if(i->right == NULL)
	  return MFUNCT_INVALID_ARGUMENT_4;

  if(type==BINOP_SUB)
    instance->def->process=binop_process_sub;
  else if(type!=BINOP_ADD)
    return MFUNCT_INVALID_ARGUMENT_1;

  return 0;	
}

static int binop_cleanup(mapidflib_function_instance_t *instance) {

	free(instance->internal_data);
	return 0;
}
	
static mapidflib_function_def_t finfo={
  "", //libname
  "BINOP", //name
  "Simulates binary operators like sum, subtract, multiply etc", //descr
  "irfrf", //argdescr
  MAPI_DEVICE_ALL, //devoid
  MAPIRES_SHM, //Method for returning results
  sizeof(unsigned long long), //shm size
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  binop_instance, //instance
  binop_init, //init
  binop_process_add, //process
  NULL, //get_result,
  NULL, //reset
  binop_cleanup, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* binop_get_funct_info();

mapidflib_function_def_t* binop_get_funct_info() {
  return &finfo;
};
