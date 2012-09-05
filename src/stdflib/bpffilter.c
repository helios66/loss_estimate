#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>
//#include <net/bpf.h>

#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "mapi_errors.h"
#include "debug.h"

#define BPF_FILTER "BPF_FILTER"

struct bpf_filter {
  struct bpf_program compiled;
};

static int bpf_instance(mapidflib_function_instance_t *instance,
			MAPI_UNUSED int fd,
			MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{

  mapiFunctArg* fargs=instance->args;
  pcap_t* pcap;
  char *str = getargstr(&fargs);
  struct bpf_filter *temp;
  
  /* 
   *	Checking Arguments
   */
  if(str == NULL)
    return MFUNCT_INVALID_ARGUMENT_1;

  if(strlen(str) < 1)  // could also force a maximum length for the filter expression
    return MFUNCT_INVALID_ARGUMENT_1;

  /*
   *	Dummy BPF filter compilation in order to check filter is OK.
   */
  if((pcap = pcap_open_dead(instance->hwinfo->link_type, instance->hwinfo->cap_length)) == NULL){
    DEBUG_CMD(Debug_Message("pcap_open_dead failed"));
    return PCAP_OPEN_DEAD_ERR;
  }
  
  temp = malloc(sizeof(struct bpf_filter));

  if(pcap_compile(pcap, ((struct bpf_program*)&((struct bpf_filter *)temp)->compiled), str, 1, 0)) {
    DEBUG_CMD(Debug_Message("bpf compilation error: %s str: \"%s\"", pcap_geterr(pcap), str));
    free(temp);
    return PCAP_BPF_ERR;
  }

  pcap_close(pcap);
  pcap_freecode((struct bpf_program *)&((struct bpf_filter *)temp)->compiled);
  free(temp);

  return 0;
}

static int bpf_init(mapidflib_function_instance_t *instance,
		    MAPI_UNUSED int fd)
//Initializes the function
{
  char* str;
  pcap_t* pcap;
  mapiFunctArg* fargs;

  fargs=instance->args;
  str =(char*) getargstr(&fargs);
  
  if((pcap = pcap_open_dead(instance->hwinfo->link_type, instance->hwinfo->cap_length)) == NULL){
    DEBUG_CMD(Debug_Message("pcap_open_dead failed"));
    return PCAP_OPEN_DEAD_ERR;
  }
  
  instance->internal_data = malloc(sizeof(struct bpf_filter));

  if(pcap_compile(pcap, ((struct bpf_program*)&((struct bpf_filter *)instance->internal_data)->compiled), str, 1, 0)) {
    DEBUG_CMD(Debug_Message("bpf compilation error: %s str: \"%s\"", pcap_geterr(pcap), str));
    return PCAP_BPF_ERR;
  }
  
  pcap_close(pcap);
 
  return 0;
}

static int bpf_process(mapidflib_function_instance_t *instance,
		       MAPI_UNUSED unsigned char* dev_pkt,
		       unsigned char* link_pkt,
		       mapid_pkthdr_t* pkt_head)
{
  return bpf_filter(((struct bpf_program)((struct bpf_filter*)instance->internal_data)->compiled).bf_insns, (unsigned char *)link_pkt,pkt_head->caplen,pkt_head->wlen);
}

static int bpf_cleanup(mapidflib_function_instance_t *instance) {
  if(instance->internal_data != NULL){
  	pcap_freecode((struct bpf_program *)&((struct bpf_filter *)instance->internal_data)->compiled);
    free(instance->internal_data);
  }
  return 0;
}

static mapidflib_function_def_t finfo={
  "", //libname
  BPF_FILTER, //name
  "BPF filter function\nParameters:\n\tBPF filter: char*", //Description
  "s", //argdescr
  MAPI_DEVICE_ALL, //Devoid
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_AUTO, //Optimization
  bpf_instance,
  bpf_init,
  bpf_process,
  NULL,
  NULL,
  bpf_cleanup,
  NULL,
  NULL, 
  NULL
};

mapidflib_function_def_t* bpf_get_funct_info();

mapidflib_function_def_t* bpf_get_funct_info() {
  return &finfo;
}
