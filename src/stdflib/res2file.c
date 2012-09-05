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
#include <ctype.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapi_errors.h"
#include "mapid.h"
#include "fhelp.h"
#include "res2file.h"
#include "stats.h"
#include "debug.h"

#define ONCE 0
#define ALWAYS 1
#define PERIODIC 2

typedef struct res2file_inst {
  int file;
  mapidflib_function_instance_t **functs;
  int *types;
  int numfuncts;
  void *data;
  int save;
  int type;
  int reset;
  unsigned long long ticks;
  unsigned long long last;
} res2file_inst_t;

static int parse_save(char* save) {
  if(strcmp(save,"-1")==0)
    return ONCE;
  else if(strcmp(save,"0")==0)
    return ALWAYS;
  else 
    return PERIODIC;
}

static int res2file_instance(mapidflib_function_instance_t *instance,
			     MAPI_UNUSED int flow_descr,
			     mapidflib_flow_mod_t *flow_mod)
{
  char *head, *savestr;
  int file;
  char *fids,*s;
  int type,fd,fid,save;
  char buf[DATA_SIZE],*cfids;
  char *types,*t,*t2,buf2[DATA_SIZE];
  int min=0;
  int reset = -1;
  mapiFunctArg* fargs=instance->args;

  if(!(types = getargstr(&fargs)))
	return(MFUNCT_INVALID_ARGUMENT_1);
  if(!(fids = getargstr(&fargs)))
	return(MFUNCT_INVALID_ARGUMENT_2);
  if(!(head = getargstr(&fargs)))
	  return(MFUNCT_INVALID_ARGUMENT_3);
  if((file = getargint(&fargs)) < 0)
	  return(MFUNCT_INVALID_ARGUMENT_4);
  else
  {
	  struct stat sbuf;
	  if(fstat(file, &sbuf) == -1)
	  {
		  DEBUG_CMD(Debug_Message("Cannot fstat() file descriptor %d", file));
		  return(MFUNCT_INVALID_ARGUMENT_4);
	  }
  }

  if((savestr = getargstr(&fargs)) == NULL)
  	return(MFUNCT_INVALID_ARGUMENT_5);

  if((save=parse_save(savestr))<0)
    return MFUNCT_INVALID_ARGUMENT_5;

  reset = getargint(&fargs);
  if(!(reset == 0 || reset == 1))
	  return(MFUNCT_INVALID_ARGUMENT_6);
  
  //Loop through fids and types and verify
  strncpy(buf,fids,DATA_SIZE);
  cfids=buf;
  strncpy(buf2,types,DATA_SIZE);
  t=buf2;

  while((s=strchr(cfids,','))!=NULL) {
    *s='\0';
    if((t2=strchr(t,','))==NULL)
      return MFUNCT_INVALID_ARGUMENT_1;
    *t2='\0';
    sscanf(cfids,"%d@%d",&fid,&fd);
    if(fhlp_get_function_instance(instance->hwinfo->gflist,fd,fid)==NULL)
      return MFUNCT_INVALID_ARGUMENT_2;
    if(min==0 || min>fid)
      min=fid;
    sscanf(t,"%d",&type);
    if(type!=R2F_RAW && type!=R2F_ULLSTR && type!=R2F_ULLSEC && 
       type!=R2F_STATS)
      return MFUNCT_INVALID_ARGUMENT_2;    
    
    cfids=s+1;
    t=t2+1;
  }
  sscanf(cfids,"%d@%d",&fid,&fd);
  if(fhlp_get_function_instance(instance->hwinfo->gflist,fd,fid)==NULL)
   return MFUNCT_INVALID_ARGUMENT_2; 
  
  if(save==PERIODIC) {
    //Move res2file in front of the other functions results are read from
    flow_mod->reorder=min;
  }

  return 0;
};

static void ullstr(mapidflib_function_instance_t *i, int fd) {
  unsigned long long *res;
  char str[1024];
  
  res=((mapidflib_result_t*)fhlp_get_res(i))->data;
  snprintf(str,1024,"%llu ",*res);
  write(fd,str,strlen(str));
};

static void ullsec(mapidflib_function_instance_t *i, int fd) {
  unsigned long long *res;
  char str[1024];
  
  res=((mapidflib_result_t*)fhlp_get_res(i))->data;
  snprintf(str,1024,"%.12Lf ",(long double)((long double)*res)/((long double)4294967296ULL));
  write(fd,str,strlen(str));
};

static void stats(mapidflib_function_instance_t *i, int fd) {
  stats_t *res;
  char str[1024];
  
  res=((mapidflib_result_t*)fhlp_get_res(i))->data;
  snprintf(str,1024,"%llu  %Lf %Lf %f %f ",res->count,res->sum,res->sum2,res->min,res->max);
  write(fd,str,strlen(str));
};

static void raw(mapidflib_function_instance_t *i, int fd) {
  mapidflib_result_t *res;

  res=((mapidflib_result_t*)fhlp_get_res(i));
  write(fd,(void*)&res->data_size,sizeof(unsigned long));
  write(fd,res->data,res->data_size);

};

static int res2file_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			mapid_pkthdr_t* pkt_head)  
{
  res2file_inst_t *i=instance->internal_data;
  int c;
  int s=0;

  if(i->save==PERIODIC) {
    if(i->last==0)
      i->last=pkt_head->ts;
    else if(pkt_head->ts-i->last>i->ticks) {
      s=1;
      i->last+=i->ticks;
      while(i->last+i->ticks<pkt_head->ts) {
      	for(c=0;c<i->numfuncts;c++)
      		write(i->file,"0 ",2);
      	write(i->file,"\n",1);
	i->last+=i->ticks;
      }
    }
  }

  if(i->save==ALWAYS || s==1) {
    //Loop through list of functions
    for(c=0;c<i->numfuncts;c++) {
      switch(i->types[c]) {
      case R2F_ULLSTR:
	ullstr(i->functs[c],i->file);
	break;
      case R2F_ULLSEC:
	ullsec(i->functs[c],i->file);
	break;
      case R2F_STATS:
	stats(i->functs[c],i->file);
	break;
      default:
	raw(i->functs[c],i->file);
      }
      if(s==1) {
	if(i->functs[c]->def->reset!=NULL && i->reset==1)
	  i->functs[c]->def->reset(i->functs[c]);
      }
    }

    write(i->file,"\n",1);
  }
  return 1;
}

static int res2file_init(mapidflib_function_instance_t *instance,
			 MAPI_UNUSED int flow_descr)
{
  res2file_inst_t *i;
  char *fids,*s,*f;
  int type,fd,fid,c;
  char *head;
  char buf[DATA_SIZE],*cfids;
  char *types,*t,*t2,buf2[DATA_SIZE];
  mapiFunctArg* fargs=instance->args;
  i=instance->internal_data=malloc(sizeof(res2file_inst_t));  
  mapidflib_function_instance_t *function;

  types=getargstr(&fargs);
  fids=getargstr(&fargs);
  head=getargstr(&fargs);
  i->file=getargint(&fargs);  

  i->save=parse_save((s=getargstr(&fargs)));
  if(i->save==PERIODIC) {
    i->ticks=fhlp_str2ull(s);
    if(i->ticks==0)
      return MFUNCT_INVALID_ARGUMENT_5;
  }
 
  i->reset=getargint(&fargs);
 
  //Count number of fids
  c=0;
  f=fids;
  while((s=strchr(f,','))!=NULL) {
    f=s+1;
    c++;
  }
  c++;
  i->functs=malloc(sizeof(mapidflib_function_instance_t*)*c);
  i->types=malloc(sizeof(int)*c);
  i->numfuncts=c;
  i->last=0;		     

  //Loop through fids and types and verify
  strncpy(buf,fids,DATA_SIZE);
  cfids=buf;
  strncpy(buf2,types,DATA_SIZE);
  t=buf2;
  c=0;
  while((s=strchr(cfids,','))!=NULL) {
    *s='\0';
    if((t2=strchr(t,','))==NULL)
      return MFUNCT_INVALID_ARGUMENT_1;
    *t2='\0';
    sscanf(cfids,"%d@%d",&fid,&fd);
    function=fhlp_get_function_instance(instance->hwinfo->gflist,fd,fid);
    i->functs[c]=function;
    if(function==NULL)
      return MFUNCT_INVALID_ARGUMENT_2;
    sscanf(t,"%d",&type);
    i->types[c++]=type;
    if(type!=R2F_RAW && type!=R2F_ULLSTR && type!=R2F_ULLSEC && 
       type!=R2F_STATS)
      return MFUNCT_INVALID_ARGUMENT_1;    
    
    cfids=s+1;
    t=t2+1;
  }
  sscanf(cfids,"%d@%d",&fid,&fd);
  function=fhlp_get_function_instance(instance->hwinfo->gflist,fd,fid);
  i->functs[c]=function;
  sscanf(t,"%d",&type);
  i->types[c++]=type;

  write(i->file,head,strlen(head));
  write(i->file,"\n",1);

  return 0;
}

static int res2file_cleanup(mapidflib_function_instance_t *instance) 
{
  res2file_inst_t *i=instance->internal_data;

  if(i->save==ONCE) {
    i->save=PERIODIC;
    res2file_process(instance,NULL,NULL,NULL);
  }

  close(i->file);
  free(i->functs);
  free(i->types);
   free(i);
  return 0;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "RES2FILE", //name
  "Stores the results from one or more functions to a file.", //descr
  "sSswsi", //argdescr
  MAPI_DEVICE_ALL, //devoid
  MAPIRES_NONE, //Method for returning results
  0, //shm size
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  res2file_instance, //instance
  res2file_init, //init
  res2file_process, //process
  NULL, //get_result,
  NULL, //reset
  res2file_cleanup, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* res2file_get_funct_info();

mapidflib_function_def_t* res2file_get_funct_info() {
  return &finfo;
};
