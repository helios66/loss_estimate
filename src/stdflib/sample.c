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
#include "mapid.h"
#include "fhelp.h"
#include "debug.h"
#include "sample.h"

//SIMPLE SAMPLING

struct sample_struct {
	short mode;
	int current;
	int sampling_period;
};


static int sample_init(mapidflib_function_instance_t *instance,
		       MAPI_UNUSED int fd)
{
	int t,mode;
	struct sample_struct *sptr;
  	mapiFunctArg* fargs;
	
	fargs=instance->args;
	t=getargint(&fargs);
	mode=getargint(&fargs);
	
	if(mode!=PERIODIC && mode!=PROBABILISTIC)
		mode=PERIODIC;

	if((instance->internal_data = malloc(sizeof(struct sample_struct))) == NULL)
	{
		DEBUG_CMD(Debug_Message("sample_init(): could not allocate internal data"));
		return(-1);
	}
	
	sptr=(struct sample_struct *)(instance->internal_data);
	sptr->mode=mode;
	
	if(mode==PERIODIC) {	
		if(t<=0) 
			t=1;
		sptr->current=0;
		sptr->sampling_period=t;
	}
	else { //probabilistic
		if(t>100)
			t=100;
		if(t<0) 
			t=0;
		sptr->sampling_period=t;
	}
		
	return 0;
}

static int sample_process(mapidflib_function_instance_t *instance,
			  MAPI_UNUSED unsigned char* dev_pkt,
			  MAPI_UNUSED unsigned char* link_pkt, 
			  MAPI_UNUSED mapid_pkthdr_t* pkt_head) 
{
  struct sample_struct *s;
  int rand;
  
  s=((struct sample_struct *)(instance->internal_data));
  
  if(s->mode==PERIODIC) {
    s->current++;
    if(s->current==s->sampling_period) {
      s->current=0;
			return 1;
    }
    return 0;
  }
  //probabilistic
  rand=random()%100;
  if(rand<=s->sampling_period)
    return 1;

   return 0;
	
}

static int sample_cleanup(mapidflib_function_instance_t *instance) {
	free(instance->internal_data);
	return 0;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "SAMPLE", //name
  "Sampling of packets\n\tReturn value: int", //descr
  "ii", //argdescr
  MAPI_DEVICE_ALL, //devoid
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_AUTO, //Optimization
  NULL,//sample_instance,
  sample_init,
  sample_process,
  NULL, //get_results
  NULL, //reset
  sample_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* sample_get_funct_info();
mapidflib_function_def_t* sample_get_funct_info() {
	return &finfo;
}
