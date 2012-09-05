#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <malloc.h>

#include "debug.h"
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapi_errors.h"
#include "mapid.h"
#include "fhelp.h"

struct threshold_data
{
  int poll_timeout;
  int in_processing;
  union
  {
    char* char_f;
    int* int_f;
    unsigned long long* ull_f;
  } value;
  
  union
  {
    char char_f;
    int int_f;
    unsigned long long ull_f;
  } lastval;

  //parameters
  int threshold_type;
  int fid;
  int fd;
  union
  {
    char char_f;
    int int_f;
    unsigned long long ull_f;
  } threshold;
  
  int threshold_bound_type;
  int timeout;
  int divider;
  int threshold_count;
  fhlp_sem_t semaphore;
  int thread; 
  int running;
};

struct threshold_shared_data
{
   fhlp_sem_t sem;
};

struct moving_window_ll
{
  union
  {
    char char_f;
    int int_f;
    unsigned long long ull_f;
  } value;
  struct moving_window_ll* next;
};


typedef enum { TYPE_CHAR=0,TYPE_INT, TYPE_UNSIGNED_LONG_LONG} threshold_type;
typedef enum { EQUAL_BOUND=0, GT_BOUND=1, LT_BOUND=2,EQUAL_D_BOUND=4,GT_D_BOUND=8,LT_D_BOUND=16} bound_type;
#define TR_POLL 64
#define TR_MW 128

static void* poll_threshold_char(void* arg);
static void* poll_threshold_int(void* arg);
static void* poll_threshold_ull(void* arg);

static int threshold_instance( mapidflib_function_instance_t *instance,
			       MAPI_UNUSED int fd,
			       MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  int tr_type;
  int tmpfid;
  int tmpfd;
  int tr_bound_type;
  mapiFunctArg* fargs=instance->args;

  tr_type=getargint(&fargs); //int threshold_type, argument#1
  switch((tr_type&63))
    {
    case TYPE_CHAR:
    case TYPE_INT:
    case TYPE_UNSIGNED_LONG_LONG:
      break;
    default:
      return  MFUNCT_INVALID_ARGUMENT_1;
    }
  //function defaults to polling if TR_MW bit not set
  
  tmpfd=getargint(&fargs);
  tmpfid=getargint(&fargs); //int function_id, argument#2
  
  if(fhlp_get_function_instance(instance->hwinfo->gflist,tmpfd,tmpfid)==NULL)
    	return MFUNCT_INVALID_ARGUMENT_2;

  getargulonglong(&fargs); //unsigned long long threshold, argument#4
  //no limits on this value

  tr_bound_type=getargint(&fargs); //int threshold_bound_type, argument #5
  switch(tr_bound_type)
    {
    case EQUAL_BOUND:
    case GT_BOUND:
    case LT_BOUND:
    case EQUAL_D_BOUND:
    case GT_D_BOUND:
    case LT_D_BOUND:
      break;
    default:
      return MFUNCT_INVALID_ARGUMENT_5;
    }
  
  //other arguments don't require validity checks.
  //shared memory
  instance->def->shm_size=sizeof(struct threshold_shared_data);
  return 0;
}


static int threshold_init(mapidflib_function_instance_t *instance,
			  MAPI_UNUSED int fd)
{
  struct threshold_data* dat;
  int tr_type;
  int tmpfid,tmpfd;
  unsigned long long threshold;
  mapidflib_function_instance_t* tmpf;
  mapiFunctArg* fargs=instance->args;
  pthread_t pthread;

  //ARGUMENT 1
  tr_type=getargint(&fargs); //int threshold_type, argument#1
  
  //We don't need this now
  getargint(&fargs);
  
  //ARGUMENT 3
  tmpfd=getargint(&fargs); //int flow descriptor, argument#3

  //ARGUMENT 4
  tmpfid=getargint(&fargs); //int function_id, argument#4

  tmpf=fhlp_get_function_instance(instance->hwinfo->gflist,tmpfd,tmpfid);
  if(tmpf==NULL)
    {
      DEBUG_CMD(Debug_Message("Function ID not found"));
      //TODO: Add errors...
      return -1;
    }
  instance->internal_data=(struct threshold_data*)malloc(sizeof(struct threshold_data));
  dat=instance->internal_data;
  dat->threshold_type=tr_type;
  dat->in_processing=0;

  //ARGUMENT 4
  threshold=getargulonglong(&fargs); //unsigned long long threshold, argument#4

  //default value....
  dat->poll_timeout=50; //50ms
  
  //ARGUMENT 5
  dat->threshold_bound_type=getargint(&fargs); //int threshold_bound_type, argument #5

  //ARGUMENT 6
  dat->timeout=getargint(&fargs); // int timeout, argument #6

  //ARGUMENT 7
  dat->divider=getargint(&fargs); // int divider, argument #7

  //ARGUMENT 8
  dat->threshold_count=getargint(&fargs); //int threshold_count argument #8

  dat->running=0;
  if(fhlp_create_semaphore(&(((struct threshold_shared_data*)instance->result.data)->sem),1)!=0)
    {
      DEBUG_CMD(Debug_Message("Semaphore ERROR"));
      return 1;
    }
  memcpy(&(dat->semaphore),&(((struct threshold_shared_data*)instance->result.data)->sem),sizeof(fhlp_sem_t));
  DEBUG_CMD(Debug_Message("Adding threshold...type: %d", dat->threshold_type&63));

  switch((dat->threshold_type&63))
    {
    case TYPE_CHAR:
      dat->threshold.char_f=(char)threshold;
      dat->value.char_f=tmpf->result.data;
      if((dat->threshold_type & TR_POLL)||(dat->threshold_type & TR_MW))
	{
	  //start the polling thread
	  dat->thread=pthread_create(&pthread, NULL, poll_threshold_char, (void*)dat);
	  //further setup in the thread
	  return 0;
	}
      break;
    case TYPE_INT:
      dat->threshold.int_f=(int)threshold;
      dat->lastval.int_f=0;
      dat->value.int_f=tmpf->result.data;
      if((dat->threshold_type & TR_POLL)||(dat->threshold_type & TR_MW))
	{
	  //start the polling thread
	  dat->thread=pthread_create(&pthread, NULL, poll_threshold_int, (void*)dat);
	  //further setup in the thread
	  return 0;
	}
      break;
    case TYPE_UNSIGNED_LONG_LONG:
      dat->threshold.ull_f=threshold;
      dat->lastval.ull_f=0;
      dat->value.ull_f=tmpf->result.data;
      if((dat->threshold_type & TR_POLL)||(dat->threshold_type & TR_MW))
	{
	  //start the polling thread
	  dat->thread=pthread_create(&pthread, NULL, poll_threshold_ull, (void*)dat);
	  //further setup in the thread
	  return 0;
	}
      break;
    }
  //Thresholding within packet processing
  dat->in_processing=1;
  return 0;
}

/*
  char's are considered fixed and not a cumulative result.
  There is no real need for a timeout in this case, since the check is done every polling interval(50ms by default)
*/
static void* poll_threshold_char(void* arg)
{
  struct threshold_data* dat=arg;
  struct timespec delay;
  struct sembuf sem_up = { 0, 1, IPC_NOWAIT };
  struct moving_window_ll* ll;
  struct moving_window_ll* lle;
  int unlimited=0;
  if (dat->threshold_type & TR_MW)
    {
      if(dat->divider>0)
	{
	  dat->poll_timeout=dat->timeout/dat->divider;
	  DEBUG_CMD(Debug_Message("Setting timeout with div to: %d", dat->poll_timeout));
	}
      else
	{
	  dat->poll_timeout=dat->timeout;
	  DEBUG_CMD(Debug_Message("Setting timeout without div(mw) to: %d", dat->poll_timeout));
	}
    }
  else
    {
      //Polling
      DEBUG_CMD(Debug_Message("Setting timeout wo div to: %d", dat->poll_timeout));
      dat->poll_timeout=dat->timeout;
      dat->divider=1;
    }
 
  delay.tv_sec=0;
  delay.tv_nsec=dat->poll_timeout*1000;//milliseconds->nanoseconds
  //no need for a moving window
  ll=(struct moving_window_ll*)malloc(sizeof(struct moving_window_ll));
  ll->next=NULL;
  lle=ll;
  if(dat->threshold_count==0) 
    {
      unlimited=1;
      dat->threshold_count=1;//set to !=0
    }
  while(1)
    {
      switch(dat->threshold_bound_type)
	{
	case EQUAL_BOUND:
	  if (dat->threshold.char_f==(*(dat->value.char_f)))
	    {
	      semop(dat->semaphore.id,&sem_up,1);
	      if(unlimited==0) dat->threshold_count--;
	    }
	  break;
	case GT_BOUND:
	   if (dat->threshold.char_f<(*(dat->value.char_f)))
	    {
	      semop(dat->semaphore.id,&sem_up,1);
	      if(unlimited==0) dat->threshold_count--;
	    }
	   break;
	case LT_BOUND:
	  if (dat->threshold.char_f>(*(dat->value.char_f)))
	    {
	      semop(dat->semaphore.id,&sem_up,1);
	      if(unlimited==0) dat->threshold_count--;
	    }
	  break;
	}
      if(dat->threshold_count==0)
	{
	  //stop thresholding
	  break;
	}
      nanosleep(&delay,NULL);      
    }
  return 0;
}


static void* poll_threshold_int(void* arg)
{
  struct threshold_data* dat=arg;
  struct timespec delay;
  struct sembuf sem_up = { 0, 1, IPC_NOWAIT };
  struct moving_window_ll* ll;
  struct moving_window_ll* lle;
  int unlimited=0;
  int intervallength=0;
  int lastval=0;
  int totval=0;

  ll=(struct moving_window_ll*)malloc(sizeof(struct moving_window_ll));
  ll->next=NULL;
  lle=ll;

  if (dat->threshold_type & TR_MW)
    {
      if(dat->divider>0)
	{
	  dat->poll_timeout=dat->timeout/dat->divider;
	}
      else
	dat->poll_timeout=dat->timeout;
    }
  else
    {
      //Polling
      dat->poll_timeout=dat->timeout;
      dat->divider=1;
    }
  delay.tv_sec=0;
  delay.tv_nsec=dat->poll_timeout*1000;//milliseconds->nanoseconds
  if(dat->threshold_count==0) 
    {
      unlimited=1;
      dat->threshold_count=1;//set to !=0
    }
  while(1)
    {
      if(dat->running)
	{
	  if(dat->threshold_type & TR_MW)
	    {
	      if(intervallength< dat->timeout)
		{
		  lle->next=(struct moving_window_ll*)malloc(sizeof(struct moving_window_ll));
		  lle->next->next=NULL;
		  lle->next->value.int_f=(*(dat->value.int_f))-lastval;
		  totval+= lle->next->value.int_f;
		  lastval=*(dat->value.int_f);
		  lle=lle->next;
		  intervallength+=dat->poll_timeout;
		}
	      else
		{
		  totval-=ll->next->value.int_f;
		  lle->next=ll->next;
		  ll->next=ll->next->next;
		  lle->next->next=NULL;
		  lle=lle->next;
		  lle->value.int_f=(*(dat->value.int_f))-lastval;
		  totval+=lle->value.int_f;
		  lastval=*(dat->value.int_f);
		}	  
	      switch(dat->threshold_bound_type)
		{
		case EQUAL_BOUND:
		  if (totval==((dat->threshold.int_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		case GT_BOUND:
		  if (totval<((dat->threshold.int_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		case LT_BOUND:
		  if (totval>((dat->threshold.int_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		}
	    }
	  else
	    {
	      
	      //ordinary polling
	      switch(dat->threshold_bound_type)
		{
		case EQUAL_BOUND:
		  //printf("Testing equality\n");
		  if ((*(dat->value.int_f))==((dat->threshold.int_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		case GT_BOUND:
		  //printf("Testing GT, totval: %llu, val: %llu\n",totval,((dat->threshold.int_f)));
		  if ((*(dat->value.int_f))>((dat->threshold.int_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		case LT_BOUND:
		  //printf("Testing LT, totval: %llu, val: %llu\n",totval,((dat->threshold.int_f)));
		  if ((*(dat->value.int_f))<((dat->threshold.int_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		case EQUAL_D_BOUND:
		  if(lastval==0) lastval=(*(dat->value.int_f));
		  if(((*(dat->value.int_f))-lastval)==((dat->threshold.int_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  lastval=*(dat->value.int_f);
		  break;
		case GT_D_BOUND:
		  if(lastval==0) lastval=(*(dat->value.int_f));
		  if(((*(dat->value.int_f))-lastval)>((dat->threshold.int_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  lastval=*(dat->value.int_f);
		  break;
		case LT_D_BOUND:
		  if(lastval==0) lastval=(*(dat->value.int_f));
		  if(((*(dat->value.int_f))-lastval)<((dat->threshold.int_f)))
		    {
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		    }
		  lastval=*(dat->value.int_f);
		  break;
		}
	    }
	  if(dat->threshold_count==0)
	    {
	      //stop thresholding
	      break;
	    }
	}
      nanosleep(&delay,NULL);      
    }
  return 0;
}

static void* poll_threshold_ull(void* arg)
{
  struct threshold_data* dat=arg;
  struct timespec delay;
  struct sembuf sem_up = { 0, 1, IPC_NOWAIT };
  struct moving_window_ll* ll;
  struct moving_window_ll* lle;
  int unlimited=0;
  int intervallength=0;
  unsigned long long lastval=0;
  unsigned long long totval=0;

  ll=(struct moving_window_ll*)malloc(sizeof(struct moving_window_ll));
  ll->next=NULL;
  lle=ll;
  if (dat->threshold_type & TR_MW)
    {
      if(dat->divider>0)
	{
	  dat->poll_timeout=dat->timeout/dat->divider;
	  DEBUG_CMD(Debug_Message("Setting timeout with div to: %d", dat->poll_timeout));
	}
      else
	dat->poll_timeout=dat->timeout;
    }
  else
    {
      //Polling
      dat->poll_timeout=dat->timeout;
      dat->divider=1;
    }
  if(dat->poll_timeout>=1000000)
    {
      delay.tv_sec=dat->poll_timeout/1000000;
      delay.tv_nsec=(((long)dat->poll_timeout)-((long)delay.tv_sec*1000000))*1000;
    } 
  else
    {
      delay.tv_sec=0;
      delay.tv_nsec=((long)dat->poll_timeout)*1000;//milliseconds->nanoseconds
    }
    DEBUG_CMD(Debug_Message("sec: %d, nsec: %lu", (int)delay.tv_sec, delay.tv_nsec));

  if(dat->threshold_count==0) 
    {
      unlimited=1;
      dat->threshold_count=1;//set to !=0
    }
  while(1)
    {
      if(dat->running)
	{
	  if(dat->threshold_type & TR_MW)
	    {
	      if(intervallength< dat->timeout)
		{
		  lle->next=(struct moving_window_ll*)malloc(sizeof(struct moving_window_ll));
		  lle->next->next=NULL;
		  lle->next->value.ull_f=(*(dat->value.ull_f))-lastval;
		  totval+= lle->next->value.ull_f;
		  lastval=*(dat->value.ull_f);
		  lle=lle->next;
		  intervallength+=dat->poll_timeout;
		}
	      else
		{
		  totval-=ll->next->value.ull_f;
		  lle->next=ll->next;
		  ll->next=ll->next->next;
		  lle->next->next=NULL;
		  lle=lle->next;
		  lle->value.ull_f=(*(dat->value.ull_f))-lastval;
		  totval+=lle->value.ull_f;
		  lastval=*(dat->value.ull_f);
		}	  
	      switch(dat->threshold_bound_type)
		{
		case EQUAL_BOUND:
		  //printf("Testing equality\n");
		  if (totval==((dat->threshold.ull_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		case GT_BOUND:
		  DEBUG_CMD(Debug_Message("Testing GT, totval: %llu, val: %llu", totval, ((dat->threshold.ull_f))));

		  if (totval>((dat->threshold.ull_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		case LT_BOUND:
		  //printf("Testing LT, totval: %llu, val: %llu\n",totval,((dat->threshold.ull_f)));
		  if (totval<((dat->threshold.ull_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		}
	    }
	  else
	    {
	      //ordinary polling
	      switch(dat->threshold_bound_type)
		{
		case EQUAL_BOUND:
		  //printf("Testing equality\n");
		  if ((*(dat->value.ull_f))==((dat->threshold.ull_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		case GT_BOUND:
		  //printf("Testing GT, totval: %llu, val: %llu\n",totval,((dat->threshold.ull_f)));
		  if ((*(dat->value.ull_f))>((dat->threshold.ull_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		case LT_BOUND:
		  //printf("Testing LT, totval: %llu, val: %llu\n",totval,((dat->threshold.ull_f)));
		  if ((*(dat->value.ull_f))<((dat->threshold.ull_f)))
		    {
		      semop(dat->semaphore.id,&sem_up,1);
		      if(unlimited==0) dat->threshold_count--;
		    }
		  break;
		case EQUAL_D_BOUND:
		  if(lastval==0) lastval=(*(dat->value.ull_f));
		  if(((*(dat->value.ull_f))-lastval)==((dat->threshold.ull_f)))
		    {
		       semop(dat->semaphore.id,&sem_up,1);
		       if(unlimited==0) dat->threshold_count--;
		    }
		  lastval=*(dat->value.ull_f);
		  break;
		case GT_D_BOUND:
		  if(lastval==0) lastval=(*(dat->value.ull_f));
		  if(((*(dat->value.ull_f))-lastval)>((dat->threshold.ull_f)))
		    {
		       semop(dat->semaphore.id,&sem_up,1);
		       if(unlimited==0) dat->threshold_count--;
		    }
		  lastval=*(dat->value.ull_f);
		  break;
		case LT_D_BOUND:
		  if(lastval==0) lastval=(*(dat->value.ull_f));
		  if(((*(dat->value.ull_f))-lastval)<((dat->threshold.ull_f)))
		    {
		       semop(dat->semaphore.id,&sem_up,1);
		       if(unlimited==0) dat->threshold_count--;
		    }
		  lastval=*(dat->value.ull_f);
		  break;
		}
	    }
	}
      if(dat->threshold_count==0)
	{
	  //stop thresholding
	  break;
	}
      nanosleep(&delay,NULL);
    }
  return 0;
}


static int threshold_process(mapidflib_function_instance_t *instance,
		      MAPI_UNUSED unsigned char* dev_pkt,
		      MAPI_UNUSED unsigned char* link_pkt, 
		      MAPI_UNUSED mapid_pkthdr_t* pkt_head)
{
  struct threshold_data* dat;
  struct sembuf sem_up = { 0, 1, IPC_NOWAIT };
  int unlimited=0;
  dat=instance->internal_data;
  dat->running=1;
  if(dat->in_processing)
    {
      if(dat->threshold_count==0) unlimited=1;
      switch((dat->threshold_type&63))
	{
	case TYPE_CHAR:
	  switch(dat->threshold_bound_type)
	    {
	    case EQUAL_BOUND:
	      if (dat->threshold.char_f==(*(dat->value.char_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      break;
	    case GT_BOUND:
	      if (dat->threshold.char_f<(*(dat->value.char_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      break;
	    case LT_BOUND:
	      if (dat->threshold.char_f>(*(dat->value.char_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      break;
	    }
	  if((dat->threshold_count==0)&&(unlimited==0))
	    {
	      //stop thresholding
	      return 0;
	    }
	  break;
	case TYPE_INT:
	  switch(dat->threshold_bound_type)
	    {
	    case EQUAL_BOUND:
	      //printf("Testing equality\n");
	      if ((*(dat->value.int_f))==((dat->threshold.int_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      break;
	    case GT_BOUND:
	      //printf("Testing GT, totval: %llu, val: %llu\n",totval,((dat->threshold.int_f)));
	      if ((*(dat->value.int_f))>((dat->threshold.int_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      break;
	    case LT_BOUND:
	      //printf("Testing LT, totval: %llu, val: %llu\n",totval,((dat->threshold.int_f)));
	      if ((*(dat->value.int_f))<((dat->threshold.int_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      break;
	    case EQUAL_D_BOUND:
	      if(dat->lastval.int_f==0) dat->lastval.int_f=(*(dat->value.int_f));
	      if(((*(dat->value.int_f))-dat->lastval.int_f)==((dat->threshold.int_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      dat->lastval.int_f=*(dat->value.int_f);
	      break;
	    case GT_D_BOUND:
	      if(dat->lastval.int_f==0) dat->lastval.int_f=(*(dat->value.int_f));
	      if(((*(dat->value.int_f))-dat->lastval.int_f)>((dat->threshold.int_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      dat->lastval.int_f=*(dat->value.int_f);
	      break;
	    case LT_D_BOUND:
	      if(dat->lastval.int_f==0) dat->lastval.int_f=(*(dat->value.int_f));
	      if(((*(dat->value.int_f))-dat->lastval.int_f)<((dat->threshold.int_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      dat->lastval.int_f=*(dat->value.int_f);
	      break;
	    }
	  if((dat->threshold_count==0)&&(unlimited==0))
	    {
	      //stop thresholding
	      return 0;
	    }
	  break;
	case TYPE_UNSIGNED_LONG_LONG:
	  switch(dat->threshold_bound_type)
	    {
	    case EQUAL_BOUND:
	      //printf("Testing equality\n");
	      if ((*(dat->value.ull_f))==((dat->threshold.ull_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      break;
	    case GT_BOUND:
	      //printf("Testing GT, totval: %llu, val: %llu\n",totval,((dat->threshold.ull_f)));
	      if ((*(dat->value.ull_f))>((dat->threshold.ull_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      break;
	    case LT_BOUND:
	      //printf("Testing LT, totval: %llu, val: %llu\n",totval,((dat->threshold.ull_f)));
	      if ((*(dat->value.ull_f))<((dat->threshold.ull_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      break;
	    case EQUAL_D_BOUND:
	      if(dat->lastval.ull_f==0) dat->lastval.ull_f=(*(dat->value.ull_f));
	      if(((*(dat->value.ull_f))-dat->lastval.ull_f)==((dat->threshold.ull_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      dat->lastval.ull_f=*(dat->value.ull_f);
	      break;
	    case GT_D_BOUND:
	      if(dat->lastval.ull_f==0) dat->lastval.ull_f=(*(dat->value.ull_f));
	      if(((*(dat->value.ull_f))-dat->lastval.ull_f)>((dat->threshold.ull_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      dat->lastval.ull_f=*(dat->value.ull_f);
	      break;
	    case LT_D_BOUND:
	      if(dat->lastval.ull_f==0) dat->lastval.ull_f=(*(dat->value.ull_f));
	      if(((*(dat->value.ull_f))-dat->lastval.ull_f)<((dat->threshold.ull_f)))
		{
		  semop(dat->semaphore.id,&sem_up,1);
		  if(unlimited==0) dat->threshold_count--;
		}
	      dat->lastval.ull_f=*(dat->value.ull_f);
	      break;
	    }
	  if(dat->threshold_count==0)
	    {
	      //stop thresholding
	      return 0;
	    }
	  break;
	}
    }
  return 1;
}

static int threshold_client_read_result(mapidflib_function_instance_t *instance,MAPI_UNUSED mapi_result_t *res) 
{
  struct sembuf sem_sub={0,-1,0};
  int condid;
  struct threshold_shared_data* data=(struct threshold_shared_data*)instance->result.data;
  condid=semget(data->sem.key,1,IPC_CREAT|0660);
  if(condid==-1)
    {
	printf("error in semget [%s:%d]\n", __FILE__, __LINE__);
	return MDLIB_SHM_ERR;
    }
  if(semop(condid,&sem_sub,1)==-1)
  {
	printf("Semaphore operation failed [%s:%d]\n", __FILE__, __LINE__);
	return MDLIB_SEM_ERR;
    }
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "THRESHOLD",
  "Thresholding function.\nParameters:\n\tfd: int\n\tfid: int\n\ttimeout: int\n\tthreshold_type: int\n\tthreshold: int, int or unsigned long long\n\tupper_bound: int\n",
  "irfiliiii",
  MAPI_DEVICE_ALL,
  MAPIRES_SHM,
  0,
  0,
  1, //filters packets
  MAPIOPT_NONE, //Optimization
  threshold_instance,
  threshold_init,
  threshold_process,
  NULL, //get_results
  NULL, //reset
  NULL,
  NULL, //client_init
  threshold_client_read_result, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* threshold_get_funct_info();

mapidflib_function_def_t* threshold_get_funct_info() {
  return &finfo;
};
