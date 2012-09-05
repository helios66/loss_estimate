#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <sys/sem.h>
#include <errno.h>

#include <signal.h>
#include <sys/mman.h>

#include "debug.h"
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapi_errors.h"
#include "mapid.h"
#include "fhelp.h"
#include "mapi.h"

#define NUM_PKTS 50 //Number of packets stored in buffer

typedef struct to_buffer {
  unsigned long read_ptr; //Pointer to the last packet that was read
  unsigned long next_read_ptr;  //Pointer to the next packet that can be read
  unsigned long write_ptr; //Pointer to where the next packet can be written
  int cap_length; //Maximum size of a captured packet
  unsigned bufsize;  //Size of buffer
  short last_pkt;  //set to 1 when last packet is being processed
  fhlp_sem_t sem; //Struct containing semaphore info
  unsigned long long read,written;
  char *buf; //Pointer to buffer
} to_buffer_t;

static int toba_instance(mapidflib_function_instance_t *instance,
			 MAPI_UNUSED int fd,
			 MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  instance->def->shm_size= sizeof(to_buffer_t)+NUM_PKTS*(sizeof(struct mapid_pkthdr)-sizeof(int)+instance->hwinfo->cap_length);

  enum toba_flg flag;
  mapiFunctArg *fargs = instance->args;

  flag = getargint(&fargs);
	
  if (flag != WAIT && flag != NOWAIT)
    return MFUNCT_INVALID_ARGUMENT_1;

  return 0;
};

static int toba_init(mapidflib_function_instance_t *instance,
		    MAPI_UNUSED int fd)
//Initializes the function
{
  to_buffer_t *mbuf;
  int ret;

  enum toba_flg flag;
  mapiFunctArg *fargs = instance->args;

  flag = getargint(&fargs);
	
  if (flag != WAIT && flag != NOWAIT)
    return MFUNCT_INVALID_ARGUMENT_1;

  mbuf=instance->result.data;
  mbuf->buf=(char*)instance->result.data+sizeof(to_buffer_t);

  //adding semaphore
  if((ret=fhlp_create_semaphore(&mbuf->sem,2))!=0) {
    DEBUG_CMD(Debug_Message("Error initializing semaphore: %d", ret));
    return ret;
  }
  
  mbuf->read_ptr=0;
  mbuf->next_read_ptr=0;
  mbuf->write_ptr=0;
  mbuf->bufsize=instance->def->shm_size - sizeof(to_buffer_t); //because hwinfo->caplen might have been changed by cook_init
  mbuf->cap_length=instance->hwinfo->cap_length;
  mbuf->last_pkt=0;
  mbuf->read=0;
  mbuf->written=0;

  return 0;
}

static int toba_process(mapidflib_function_instance_t *instance,
			unsigned char* dev_pkt,
			unsigned char* pkt,
			mapid_pkthdr_t* pkt_head)  
{
  to_buffer_t *mbuf=instance->result.data;
  unsigned new_write=0, new_next_write;
  char* write; //Pointer to memory where packet will be written;
  struct sembuf sem_add={0,1,IPC_NOWAIT};
  struct sembuf sem_wait_add={1,1,IPC_NOWAIT};
  struct sembuf sem_wait={1,0,0};
  int isfull=0;

  new_next_write = mbuf->write_ptr + pkt_head->caplen + sizeof(struct mapid_pkthdr)-sizeof(int) + sizeof(unsigned long);

  if(new_next_write >= mbuf->bufsize-sizeof(unsigned long)) {
    //Check to see if there is room at the end of the buffer for a new packet
    //If not, wrap to beginning of buffer
    if (mbuf->write_ptr >= mbuf->next_read_ptr) {
      new_next_write = pkt_head->caplen + sizeof(struct mapid_pkthdr)-sizeof(int);
      new_write = 0;
    }
    else {
	    isfull = 1;
    }
  }
  else {
    new_write = mbuf->write_ptr + sizeof(unsigned long*);
  }
  

  if(instance->hwinfo->offline==3) {
    mbuf->last_pkt=1;
    //  printf("LAST_PKT=1\n");
  }

    //Check to see if buffer is full
  if ((new_next_write >= mbuf->read_ptr && new_next_write <= mbuf->next_read_ptr)
	|| (new_write >= mbuf->read_ptr && new_write <= mbuf->next_read_ptr)
	|| (new_write <= mbuf->read_ptr && new_next_write >= mbuf->next_read_ptr) 
	|| (new_write >= mbuf->read_ptr && new_next_write <= mbuf->next_read_ptr)
	|| isfull ){
    
    //If offline flow, wait till client reads packet.
    if(instance->hwinfo->offline>0) {
      if (semop(mbuf->sem.id,&sem_wait_add,1) != 0){
	      DEBUG_CMD(Debug_Message("error semop 1")); //Wait till it is 0 again
      }
      //printf("WAIT\n");
      if (semop(mbuf->sem.id,&sem_wait,1) != 0){
	      DEBUG_CMD(Debug_Message("error semop 2")); //Wait till it is 0 again
      }
      toba_process(instance,dev_pkt,pkt,pkt_head);
    } 
    //else {
    //  DEBUG_CMD(printf("TO_BUFFER : Packet dropped\n"));
    //}
  }
  else {
    (*(unsigned long*)(mbuf->buf + mbuf->write_ptr)) = new_write;
    //Enough space in buffer for the new packet
    write = mbuf->buf + new_write;
    memcpy(write, pkt_head, sizeof(struct mapid_pkthdr)-sizeof(int));
    write += sizeof(struct mapid_pkthdr)-sizeof(int);
    memcpy(write, pkt, pkt_head->caplen);
    mbuf->written++;

    if(semop(mbuf->sem.id,&sem_add,1)==-1)
      {
	//error....
	DEBUG_CMD(Debug_Message("Error with semaphore, id=%d", mbuf->sem.id));
	perror("Error msg");
	return MFUNCT_SEM_ERROR;
	/* should be handled in some way */
      }

    mbuf->write_ptr=new_next_write;
  }
  return 1;
}

/*static int toba_get_result(mapidflib_function_instance_t *instance,
			   mapidflib_result_t **res)
{
  (*res)=&instance->result;
  return 0;
}
*/

static int toba_cleanup(mapidflib_function_instance_t *instance) 
{
  to_buffer_t *mbuf;
  mbuf=instance->result.data;
  
  fhlp_free_semaphore(&mbuf->sem);  
 
  return 0;
}

static int toba_client_read_result(mapidflib_function_instance_t *instance,mapi_result_t *res) 
{
  to_buffer_t *tb=instance->result.data;
  char *buf=(char*)instance->result.data+sizeof(to_buffer_t);
  struct sembuf sem_sub={0,-1,0};  
  struct sembuf sem_wait_sub={1,-1,IPC_NOWAIT};  
  struct mapipkt* pkt=NULL;
  union semun {
		int val;
		struct semid_ds *buf;
		ushort * array;
	} argument;

  int condid, errno2;

  mapiFunctArg *fargs = instance->args;
  enum toba_flg flag = getargint(&fargs);

  if (flag == WAIT) {
    sem_sub.sem_num = 0;
    sem_sub.sem_op = -1;
    sem_sub.sem_flg = 0;
  } else if (flag == NOWAIT) {
    sem_sub.sem_num = 0;
    sem_sub.sem_op = -1;
    sem_sub.sem_flg = IPC_NOWAIT;
  }

  if(tb->last_pkt==1 && tb->written==tb->read) {
    res->res=NULL;
    res->size=0;
    //printf("LAST PKT\n");
    return 0;
  }

  argument.val = 1;  
  //wait for packet(semaphore blocks when no packets were ready in the buffer)
  condid=semget(tb->sem.key,1,IPC_CREAT|0660);

  if((errno2=semop(condid,&sem_sub,1))==-1) {
      if (errno == EAGAIN && flag == NOWAIT) {
	res->res = 0;
	res->size = 0;
	semop(condid, &sem_wait_sub, 1);
	return 0;
      }
      else {
	printf("Error in semop [%s:%d]\n", __FILE__, __LINE__);
	return MAPI_SEM_ERR;
      }
  }


  tb->read++;
  tb->read_ptr = *(unsigned long*)(buf + tb->next_read_ptr);
  pkt=(struct mapipkt*)(buf+tb->read_ptr);
  tb->next_read_ptr = tb->read_ptr + pkt->caplen + sizeof(struct mapid_pkthdr)-sizeof(int);

  res->res=pkt;
  res->size=pkt->caplen+sizeof(struct mapid_pkthdr)-sizeof(int);
  semop(condid,&sem_wait_sub,1);
  return 0;
}

static mapidflib_function_def_t finfo={
  "", //libname
  "TO_BUFFER", //name
  "Copies packets to a buffer that can be read by the client",  //descr
  "i", //argdescr
  MAPI_DEVICE_ALL, //devtype
  MAPIRES_SHM,
  0, //shm size. Set by instance
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  toba_instance,
  toba_init,
  toba_process,
  NULL, //get_result
  NULL, //reset
  toba_cleanup,
  NULL, //client_init
  toba_client_read_result,
  NULL //client_cleanup
};

mapidflib_function_def_t* toba_get_funct_info();
mapidflib_function_def_t* toba_get_funct_info() {
  return &finfo;
};

