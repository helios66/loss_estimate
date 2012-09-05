#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/sem.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapi_errors.h"
#include "mapid.h"
#include "fhelp.h"
#include "debug.h"
#include "bucket.h"

#define BUCKET_SIZE 1000

#define ONCE 0
#define ALWAYS 1
#define PERIODIC 2

struct bucket_ringbuffer
{
  unsigned int readpos;
  unsigned int writepos;
  unsigned int ringsize;
  int bucket_offset;
  fhlp_sem_t semaphore;
};

struct bucket_function_data
{
  unsigned long long ticks;
  unsigned long long last;
  mapidflib_function_instance_t* funct;
  int fd;
  int fid;
  int reset;
  int save;
};

mapidflib_function_def_t* bucket_get_funct_info();

static int parse_save(char* save) {
  if(strcmp(save,"-1")==0)
    return ONCE;
  else if(strcmp(save,"0")==0)
    return ALWAYS;
  else 
    return PERIODIC;
}


static int bucket_instance( mapidflib_function_instance_t *instance,
			    MAPI_UNUSED int flow_descr,
			    MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  mapiFunctArg* fargs;
  int fd,fid;
  char* str_time;
  

  fargs=instance->args;
  fd=getargint(&fargs);
  fid=getargint(&fargs);
  str_time = getargstr(&fargs);
  
  if(str_time==NULL)
      return MFUNCT_INVALID_ARGUMENT;
	  
  if(fhlp_get_function_instance(instance->hwinfo->gflist,fd,fid)==NULL)
    {
      DEBUG_CMD(Debug_Message("Function not found: %u", fid));
      return MFUNCT_INVALID_ARGUMENT;
    }
    
  if(parse_save(str_time)==PERIODIC) {
    //Move res2file in front of the other function results are read from
    flow_mod->reorder=fid;
  }
    

  return 0;
}

static int bucket_init(mapidflib_function_instance_t *instance,
		       MAPI_UNUSED int flow_descr)
{
  struct bucket_function_data* fdata;
  struct bucket_ringbuffer* rbuf;
  unsigned long long timeout;
  char *s;
  mapiFunctArg* fargs;
  int fid,fd;
  fargs=instance->args;
  fd=getargint(&fargs);
  fid=getargint(&fargs);
  s=getargstr(&fargs);  
  timeout=fhlp_str2ull(s);

  instance->internal_data=(struct bucket_function_data*)malloc(sizeof(struct bucket_function_data));
  fdata=(struct bucket_function_data*)instance->internal_data;
  rbuf=(struct bucket_ringbuffer*)instance->result.data;
  rbuf->readpos=0;
  rbuf->writepos=0;
  rbuf->ringsize=BUCKET_SIZE;
  rbuf->bucket_offset=sizeof(struct bucket_ringbuffer);
  if((fdata->funct=fhlp_get_function_instance(instance->hwinfo->gflist,fd,fid))==NULL) {
    return MFUNCT_INVALID_ARGUMENT;
  }
  fdata->last=0;
  fdata->ticks=timeout;
  fdata->save=parse_save(s);
  if(fdata->save==PERIODIC && fdata->ticks==0)
      return MFUNCT_INVALID_ARGUMENT_3;
  
  
  fdata->reset=getargint(&fargs);

  if(!(fdata->reset==0 || fdata->reset==1))
  	return MFUNCT_INVALID_ARGUMENT;
  	
  if(fhlp_create_semaphore(&rbuf->semaphore,1)!=0)
    {
      DEBUG_CMD(Debug_Message("Semaphore ERROR"));
    }
  return 0;
}

static int bucket_process(mapidflib_function_instance_t *instance,
			  MAPI_UNUSED unsigned char* dev_pkt,
			  MAPI_UNUSED unsigned char* link_pkt, 
			  mapid_pkthdr_t* pkt_head) 
{
  struct bucket_function_data* fdata;
  struct bucket_ringbuffer* rbuf;
  unsigned long long *res;
  int s=0;
  struct sembuf sem_add={0,1,IPC_NOWAIT};
  
  fdata=(struct bucket_function_data*)instance->internal_data;
  rbuf=(struct bucket_ringbuffer*)instance->result.data;
  res=(unsigned long long*)(fhlp_get_res(fdata->funct)->data);
  
  if(fdata->save==PERIODIC) {
    if(fdata->last==0)
      fdata->last=pkt_head->ts;
    else if(pkt_head->ts-fdata->last>fdata->ticks) {
      s=1;
      fdata->last+=fdata->ticks;
      while(fdata->last+fdata->ticks<pkt_head->ts) {
		if(rbuf->writepos<rbuf->ringsize) {
			rbuf->writepos++;
			if(rbuf->writepos>=rbuf->ringsize) 
		  		rbuf->writepos=0;		  		
		  	((struct bucket_data*)(((char*)rbuf)+rbuf->bucket_offset))[rbuf->writepos].timestamp=fdata->last;
   		    ((struct bucket_data*)(((char*)rbuf)+rbuf->bucket_offset))[rbuf->writepos].data=(unsigned long long)0;
	     	if(semop(rbuf->semaphore.id,&sem_add,1)==-1) {
		      //error....
		      DEBUG_CMD(Debug_Message("Error: %u,%u", errno, EINVAL));
	      /* should be handled in some way */
		    }
		fdata->last+=fdata->ticks;   		    		
      }
    }
  }
  }
  
  if (fdata->save==ALWAYS || s==1)
    {
      //out of the bucket
      if(rbuf->writepos<rbuf->ringsize) {
	  //allow overwrite of old data...
	  rbuf->writepos++;
	  if(rbuf->writepos>=rbuf->ringsize) 
	    rbuf->writepos=0;
	  ((struct bucket_data*)(((char*)rbuf)+rbuf->bucket_offset))[rbuf->writepos].timestamp=fdata->last;
	  ((struct bucket_data*)(((char*)rbuf)+rbuf->bucket_offset))[rbuf->writepos].data=*res;
	  if(semop(rbuf->semaphore.id,&sem_add,1)==-1)
	    {
	      //error....
	      DEBUG_CMD(Debug_Message("Error: %u,%u", errno, EINVAL));
	      /* should be handled in some way */
	    }
	  if(fdata->funct->def->reset!=NULL && fdata->reset==1)
	    {
	      //maybe move this to fhlp.c?
	      fdata->funct->def->reset(fdata->funct);
	    }
      }
    }

  return 1;
}

static int bucket_client_read_result(mapidflib_function_instance_t *instance,mapi_result_t *res)
{
  struct bucket_ringbuffer* data;
  struct sembuf sem_sub={0,-1,0};
  int condid;
  data=(struct bucket_ringbuffer*)instance->result.data;
  res->size=sizeof(struct bucket_data);
  condid=semget(data->semaphore.key,1,IPC_CREAT|0660);
  
  if(condid==-1)
    {
      printf("error in semget [%s:%d]\n", __FILE__, __LINE__);
    }
  if(semop(condid,&sem_sub,1)==-1)
    {
      printf("Error in semop [%s:%d]\n", __FILE__, __LINE__);
      return MAPI_SEM_ERR;
    }
  res->res=((char*)data)+data->bucket_offset+sizeof(struct bucket_data)*data->readpos;
  data->readpos++;
  if(data->readpos>=data->ringsize) data->readpos=0;
  return 0;
}

static int bucket_client_init(MAPI_UNUSED mapidflib_function_instance_t *instance, MAPI_UNUSED void* data)
{
  //done by mapi
  return 0;
}

static int bucket_cleanup(mapidflib_function_instance_t *instance) {
	
	struct bucket_ringbuffer* rbuf;
	rbuf = (struct bucket_ringbuffer*)instance->result.data;

	fhlp_free_semaphore(&rbuf->semaphore);
	free(instance->internal_data);
	return 0;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "BUCKET", //name
  "Sampling of packets\n\tReturn value: int\nParameters:\n\tint fd of resultfunction\n\tint fid of resultfunction", //descr
  "rfsi", //argdescr
  MAPI_DEVICE_ALL, //devoid
  MAPIRES_SHM,
  sizeof(struct bucket_ringbuffer)+(BUCKET_SIZE)*sizeof(struct bucket_data),
  0,
  0,
  MAPIOPT_NONE, //Optimization
  bucket_instance,
  bucket_init,
  bucket_process,
  NULL, //get_results
  NULL, //reset
  bucket_cleanup, //cleanup
  bucket_client_init,	//client_init
  bucket_client_read_result, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* bucket_get_funct_info();
mapidflib_function_def_t* bucket_get_funct_info() {
	return &finfo;
}
