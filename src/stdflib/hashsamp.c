#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>		/* DLT_EN10MB */
#include <assert.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapi_errors.h"
#include "mapid.h"
#include "fhelp.h"
#include "hashsamp.h"
#include <sys/sem.h>
#include <netinet/in.h>
#include <asm/types.h>
#include <net/ethernet.h>      /* For ETHERTYPE_IP */
#include "debug.h"

#define NUM_STATS 40


typedef struct samp_buffer {
  unsigned long read_ptr; //Pointer to the next sample data that can be read
  unsigned long write_ptr; //Pointer to where the next sample can be written
  char* buf; //Pointer to buffer
  int cap_length; //size of sample
  unsigned bufsize;  //Size of buffer
  fhlp_sem_t sem;
  unsigned int samppart;
  unsigned int keepresults;
  unsigned int count1;
  unsigned int count2;
} samp_buffer_t;


//Hashing based sampling

/* IP and TCP Packet code from linux kernel */
struct iphdr {
  //we use i386->little endian
  __u8    ihl:4,
    version:4;
  __u8    tos;
  __u16   tot_len;
  __u16   id;
  __u16   frag_off;
  __u8    ttl;
  __u8    protocol;
  __u16   check;
  __u32   saddr;
  __u32   daddr;
};

struct tcphdr {
  __u16   source;
  __u16   dest;
  __u32   seq;
  __u32   ack_seq;
  __u16   res1:4,
    doff:4,
    fin:1,
    syn:1,
    rst:1,
    psh:1,
    ack:1,
    urg:1,
    ece:1,
    cwr:1;
  __u16   window;
  __u16   check;
  __u16   urg_ptr;
};

struct udphdr {
        __u16   source;
        __u16   dest;
        __u16   len;
        __u16   check;
};



/* Hashing Code from the linux kernel*/

#define __jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO      0x9e3779b9


static inline int jhash_3words(int a, int b, int c, int initval)
{
        a += JHASH_GOLDEN_RATIO;
        b += JHASH_GOLDEN_RATIO;
        c += initval;

        __jhash_mix(a, b, c);

        return c;
}


static int hashsamp_instance(mapidflib_function_instance_t *instance,
			     MAPI_UNUSED int fd,
			     MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  //check arguments
  mapiFunctArg* fargs;
  int samppart;
  int keepresults;
  
  fargs=instance->args;
  samppart=getargint(&fargs);
  keepresults=getargint(&fargs);

  if((samppart>1024)||(samppart<1))
    {
      return  MFUNCT_INVALID_ARGUMENT_1;
    }
  //keepresults is boolean
  if(keepresults!=0)
    {
      //we need shared memory
      int size;
      size=NUM_STATS*sizeof(struct sample)+sizeof(samp_buffer_t);
      instance->def->shm_size=size;
    }
  return 0;
}


static int hashsamp_init(mapidflib_function_instance_t *instance,
			 MAPI_UNUSED int fd)
{
  mapiFunctArg* fargs=instance->args;
  samp_buffer_t * sbuf;
  int samppart;
  int keepresults;
  samppart=getargint(&fargs);
  keepresults=getargint(&fargs);
  
  if(keepresults!=0)
    {
      samp_buffer_t* i;
      sbuf=instance->result.data;
      //we need a backup copy, to read keepresults
      i=instance->internal_data=malloc(sizeof(samp_buffer_t));
      i->keepresults=keepresults;
      sbuf->keepresults=keepresults;
    }
  else
    {
      sbuf=instance->internal_data=malloc(sizeof(samp_buffer_t));
      sbuf->keepresults=0;
    }
  sbuf->samppart=samppart;
  
  if(sbuf->keepresults!=0)
    {
      int ret;
      //create semaphore
      if((ret=fhlp_create_semaphore(&sbuf->sem,1))!=0) {
	DEBUG_CMD(Debug_Message("Error initializing semaphore: %d", ret));
	return ret;
      }
      sbuf->read_ptr=0;
      sbuf->write_ptr=0;
      sbuf->buf=(char*)sbuf+sizeof(samp_buffer_t);
      sbuf->cap_length=sizeof(struct sample);
      sbuf->bufsize=NUM_STATS*sizeof(struct sample);
      
    }
  return 0;
}

static int hashsamp_process(mapidflib_function_instance_t *instance,
		     MAPI_UNUSED unsigned char* dev_pkt,
		     unsigned char* pkt,
		     mapid_pkthdr_t* pkt_head)
{
  samp_buffer_t *mbuf=instance->internal_data;
  const char* data = NULL;

  struct iphdr *iphdr;
  struct tcphdr *tcphdr;
  struct udphdr *udphdr;
  unsigned int s;
  unsigned int d;
  unsigned int hash;

  if(mbuf->keepresults!=0)
    mbuf=instance->result.data;
  
  if (instance->hwinfo->link_type == DLT_EN10MB) /* ethernet */ {
      //pkt parsing...
      //first 14 bytes should be pkt_head...
      data=(const char*)pkt;
      if((data[12]!=8)||(data[13]!=0)) {
        //this is not an IP packet, (0x0800)
        return 0;
      }
      data=data+14; //ethernet header is 14bytes
  } else if (instance->hwinfo->link_type == DLT_CHDLC ) {
      data = (const char*)pkt;
	  if (ntohs(*(uint16_t*)(dev_pkt + 18)) != ETHERTYPE_IP) {
        //this is not an IP packet
        return 0;
      }
      data=data+20;
  } else {
	  assert(0);
  }
  
  iphdr=(struct iphdr*)data;
  //we only sample TCP and UDP traffic
  //based on source IP&PORT, dest IP&PORT and the protocol
  if(iphdr->protocol!=6)
    {
      //TCP is IP protocol 6
      if(iphdr->protocol!=17)
	{
	  //UDP is IP protocol 17
	  return 0;
	}
    }
  
  data=data+4*iphdr->ihl;//ihl is in 32bit words...
  if (iphdr->protocol==6)
    {
      tcphdr=(struct tcphdr*)data;
      s=tcphdr->source;
      d=tcphdr->dest;
    }
  else
    {
      udphdr=(struct udphdr*)data;
      s=udphdr->source;
      d=udphdr->dest;
    }

  hash=((unsigned int)jhash_3words(iphdr->saddr, (iphdr->daddr ^ iphdr->protocol),(s | (d<< 16)),6564987))%1024;
  DEBUG_CMD(Debug_Message("hash: %d, threshold: %u", hash, mbuf->samppart));
  //we don't need any futher processing if no results should be kept.
  if(mbuf->keepresults==0)
    {
      if(hash<mbuf->samppart) return 1;
      return 0;
    }
  if(hash<mbuf->samppart)
    {
      //OK, hash succeeded
      struct sample* thesample=(struct sample*)malloc(sizeof(struct sample));
      
      unsigned new_write=mbuf->write_ptr+mbuf->cap_length;
      char* write;
      struct sembuf sem_add={0,1,IPC_NOWAIT};
      
      DEBUG_CMD(Debug_Message("Hash succeeded"));
      thesample->source_ip=iphdr->saddr;
      thesample->dest_ip=iphdr->daddr;
      thesample->protocol=iphdr->protocol;
      thesample->sourceport=ntohs(s);
      thesample->destport=ntohs(d);
      thesample->timestamp=pkt_head->ts;
      if(thesample->protocol==6)
      {
	tcphdr=(struct tcphdr*)data;
	thesample->sequence=ntohl(tcphdr->seq);
	thesample->tcp_flags=0;
	if(tcphdr->fin==1) thesample->tcp_flags+=TCP_FIN;
	if(tcphdr->syn==1) thesample->tcp_flags+=TCP_SYN;
	if(tcphdr->rst==1) thesample->tcp_flags+=TCP_RST;
	if(tcphdr->ack==1) thesample->tcp_flags+=TCP_ACK;
	if(tcphdr->psh==1) thesample->tcp_flags+=TCP_PSH;
      }
      
      if(new_write+mbuf->cap_length>mbuf->bufsize)
	//Check to see if there is room at the end of the buffer for a new packet
	//If not, wrap to beginning of buffer
	new_write=0;
      
      if(new_write==mbuf->read_ptr
	 || (new_write<mbuf->write_ptr && new_write>mbuf->read_ptr) 
	 || (mbuf->write_ptr<mbuf->read_ptr && new_write>mbuf->read_ptr && new_write>mbuf->write_ptr)){
	//Check to see if buffer is full
	DEBUG_CMD(Debug_Message("Packet dropped"));
      }
      else {
	//Enough space in buffer for the new packet
	write=mbuf->buf+mbuf->write_ptr;
	memcpy(write,thesample,sizeof(struct sample));
	
	if(semop(mbuf->sem.id,&sem_add,1)==-1)
	  {
	    //error....
	    DEBUG_CMD(Debug_Message("Error"));
	    /* should be handled in some way */
	  }
	mbuf->write_ptr=new_write;
	mbuf->count1++;
      }
      free(thesample);	
      return 1;
    }
  return 0;
}


static int hashsamp_cleanup(mapidflib_function_instance_t *instance) 
{
  samp_buffer_t *mbuf;
  mbuf=instance->internal_data;
  if(mbuf->keepresults!=0)
  {
    mbuf=instance->result.data;
    
    fhlp_free_semaphore(&mbuf->sem);
  }

  free(instance->internal_data);
 
  return 0;
}



static int hashsamp_client_read_result(mapidflib_function_instance_t *instance,mapi_result_t *res) 
{
  samp_buffer_t *tb=instance->result.data;
  char *buf=(char*)instance->result.data+sizeof(samp_buffer_t);
  struct sembuf sem_sub={0,-1,0};  
  union semun {
		int val;
		struct semid_ds *buf;
		ushort * array;
	} argument;

  int condid;

  argument.val = 1;  
  //wait for packet(semaphore blocks when no packets ware ready in the buffer)
  condid=semget(tb->sem.key,1,IPC_CREAT|0660);
  //
  if((errno=semop(condid,&sem_sub,1))==-1)
    {
      printf("Error in semop [%s:%d]\n", __FILE__, __LINE__);
      return MAPI_SEM_ERR;
    }
  
  //Wait for new pkt

  res->res=buf+tb->read_ptr;
  tb->read_ptr=tb->read_ptr+tb->cap_length;
  if(tb->read_ptr+tb->cap_length>tb->bufsize)
    tb->read_ptr=0;

  res->size=sizeof(struct sample);

  //semop(condid,&sem_wait_sub,1);
  return 0;
}

static int hashsamp_client_init(MAPI_UNUSED mapidflib_function_instance_t *instance, MAPI_UNUSED void* data){
	return 0;
} 	 

static mapidflib_function_def_t finfo={
  "", //libname
  "HASHSAMP", //name
  "Implements hashing based sampling",  //descr
  "ii", //argdescr
  MAPI_DEVICE_ALL, //devtype
  MAPIRES_SHM,
  0, //shm size. Set by instance
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_AUTO, //Optimization
  hashsamp_instance,
  hashsamp_init,
  hashsamp_process,
  NULL, //get_result
  NULL, //reset
  hashsamp_cleanup,
  hashsamp_client_init, //client_init
  hashsamp_client_read_result,
  NULL //client_cleanup
};

mapidflib_function_def_t* hashsamp_get_funct_info();
mapidflib_function_def_t* hashsamp_get_funct_info() {
  return &finfo;
};
