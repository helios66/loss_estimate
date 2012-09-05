#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapi_errors.h"
#include "mapid.h"
#include "fhelp.h"

//Timestamp format can be relative: +1ms +1.2s etc
//or it can be absolute following the syntax "%Y-%m-%d %H:%M:%S"


typedef struct startstop {
  unsigned long long first;
  unsigned long long first_processed;
  unsigned long long last;
} startstop_t;

typedef struct startstop_internal {
  unsigned long long start;
  unsigned long long stop;
} startstop_internal_t;



static int startstop_instance(mapidflib_function_instance_t *instance,
			      MAPI_UNUSED int fd,
				 MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  mapiFunctArg* fargs;
  char *s1, *s2;
  struct tm t;
  
  fargs = instance->args;
  s1 = getargstr(&fargs);
  s2 = getargstr(&fargs);

  if((!s1 || !s2) || (s1[0]=='+' && s2[0]!='+'))
	  return(MFUNCT_INVALID_ARGUMENT);

  	if( (s1[0]!='+' && strptime(s1,"%Y-%m-%d %H:%M:%S",&t)==NULL) || (s2[0]!='+' && strptime(s2,"%Y-%m-%d %H:%M:%S",&t)==NULL) )
  		return MFUNCT_INVALID_ARGUMENT;	
  	
  return 0;
};

static int startstop_process_absolute(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			mapid_pkthdr_t* pkt_head)  
{
  startstop_internal_t *ssi=instance->internal_data;
  
  if(ssi->start!=0 && ssi->start > pkt_head->ts)
    return 0;

  if(ssi->stop!=0 && ssi->stop<pkt_head->ts)
    return 0;

  return 1;
}


static int startstop_init(mapidflib_function_instance_t *instance,
			  MAPI_UNUSED int fd)
{
  struct tm t;
  time_t tt;
  char *s1, *s2;
    
  mapiFunctArg* fargs=instance->args;
  startstop_t *ss=instance->result.data;
  startstop_internal_t *ssi=malloc(sizeof(startstop_internal_t));

  instance->internal_data=ssi;

  s1 = getargstr(&fargs);
  s2 = getargstr(&fargs);


  if(s1[0]=='+') {
	ssi->start=fhlp_str2ull(s1);
  	ssi->stop=ssi->start+fhlp_str2ull(s2);
  } else {
  	strptime(s1,"%Y-%m-%d %H:%M:%S",&t);
  	tt=mktime(&t);
  	ssi->start=(unsigned long long)tt << 32;
  	
  	if(s2[0]!='+') {
	  	strptime(s2,"%Y-%m-%d %H:%M:%S",&t);
	  	tt=mktime(&t);
	  	ssi->stop=(unsigned long long)tt << 32;	  	
  	} else
  		ssi->stop=ssi->start+fhlp_str2ull(s2);
  	  	
  	instance->def->process=startstop_process_absolute;
  	
  }
    
  ss->first=0;
  ss->last=0;
  ss->first_processed=0;
//  printf("start: %lld stop:%lld stop-start=%lld\n",ssi->start>>32,ssi->stop>>32,(ssi->stop-ssi->start)>>32);

  return 0;
}


static int startstop_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			mapid_pkthdr_t* pkt_head)  
{
  startstop_internal_t *ssi=instance->internal_data;
  startstop_t *ss=instance->result.data;

  if(ss->first==0)
    ss->first=pkt_head->ts;

  
  if(ssi->start>0 && ssi->start+ss->first>pkt_head->ts)
    return 0;

  if(ssi->stop>0 && ssi->stop+ss->first<pkt_head->ts)
    return 0;

  if(ss->first_processed==0)
    ss->first_processed=pkt_head->ts;

  ss->last=pkt_head->ts;

  return 1;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "STARTSTOP", //name
  "Function stat specifies a specific period of time that processed packets must belong to. Returns the timestamp of the first and last packet that was processed", //descr
  "ss", //argdescr
  MAPI_DEVICE_ALL, //devtype
  MAPIRES_SHM, //Method for returning results
  sizeof(startstop_t), //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_AUTO, //Optimization
  startstop_instance, //instance
  startstop_init, //init
  startstop_process, //process
  NULL, //get_result,
  NULL, //reset
  NULL, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* startstop_get_funct_info();

mapidflib_function_def_t* startstop_get_funct_info() {
  return &finfo;
};



