#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <pthread.h>
#include <dagnew.h>
#include <dagapi.h>
#include "mapi_errors.h"
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"


#define BUFSIZE 500000

typedef struct erf_instance {
  unsigned long long maxpkts;
  unsigned long long pkts;
  int file;
  int count;
  unsigned char *buf,*next;
} erf_instance_t;

static int to_erf_instance(mapidflib_function_instance_t *instance,
			   MAPI_UNUSED int fd,
			   MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  mapiFunctArg* a=instance->args;
  int type = getargint(&a);
  if(type==MFF_RAW || type==MFF_DAG_ERF)
    return 0;

  
  return MFUNCT_COULD_NOT_APPLY_FUNCT;
}

static int to_erf_init(mapidflib_function_instance_t *instance,
		       MAPI_UNUSED int fd)
//Initializes the function
{
  int *res;
  erf_instance_t *i=malloc(sizeof(erf_instance_t)); 

  i->next=i->buf=malloc(sizeof(unsigned char)*instance->hwinfo->cap_length*BUFSIZE);
  i->count=0;

  mapiFunctArg* fargs=instance->args;
  getargint(&fargs);

  //Open file for writing
  i->file=getargint(&fargs);

  if(i==NULL||i->file<0) {
    free(i);
    return MFUNCT_COULD_NOT_INIT_FUNCT;
  }

  i->maxpkts=getargulonglong(&fargs);
  i->pkts=0;
  instance->internal_data=i;
  res=instance->result.data;
  *res=1;

  return 0;
}

static int to_erf_process(mapidflib_function_instance_t *instance,
			  unsigned char* dev_pkt,
			  MAPI_UNUSED unsigned char* link_pkt,
			  MAPI_UNUSED mapid_pkthdr_t* pkthdr)
{
  int l;
  erf_instance_t *i=instance->internal_data;
  int *res=instance->result.data;
  dag_record_t *rec=(dag_record_t*)dev_pkt;

  if(i->pkts >= i->maxpkts && i->maxpkts!=0) {      
    *res=0;
    return 1;
  }

  if(i->count<BUFSIZE) {
    l=ntohs(rec->rlen);
    memcpy(i->next,dev_pkt,l);
    i->next+=l;
    i->count++;
  } else {
    write(i->file,i->buf,i->next-i->buf);
    i->next=i->buf;
    i->count=0;
  }
  
  i->pkts++;

  return 1;
}

static int to_erf_cleanup(mapidflib_function_instance_t *instance) {
  erf_instance_t *i=instance->internal_data;

  /* Flush buffer to file */
  if (i->count > 0) {
    write(i->file,i->buf,i->next-i->buf);
    i->next=i->buf;
    i->count=0;
  }

  if (i!=NULL && i->file)
    close(i->file);
    
  free(i->buf);
  free(i);
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "TO_FILE",
  "TO_FILE saves packetflow into DAG erf file.\nParameters:\n\tfilename : char*\n\tmaxpos: unsigned long long",
  "iwl",
  MAPI_DEVICE_DAG,
  MAPIRES_SHM,
  sizeof(int), //shm size
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_AUTO,
  to_erf_instance,
  to_erf_init,
  to_erf_process,
  NULL, //get_result
  NULL, //reset
  to_erf_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* to_erf_get_funct_info();
mapidflib_function_def_t* to_erf_get_funct_info() {
  return &finfo;
};
