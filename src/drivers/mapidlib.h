#ifndef _MAPIDLIB_H
#define _MAPIDLIB_H 1

#include <pthread.h>
#include <sys/types.h>

#include "flist.h"
#ifdef WITH_PRIORITIES
#include "priorities.h"
#endif
#include "mapid.h"

#define MDL_AFTER 1

typedef struct mapid_pkthdr {
    unsigned long long ts; /* 64-bit timestamp of packet*/
    unsigned short ifindex; //Interface index
    unsigned caplen;     /* length of portion present */
    unsigned wlen;        /* length this packet (off wire) */
    int color;		 /* colorize the packet for optimizations */
} mapid_pkthdr_t;

typedef struct tap
{
	int id;
	char *vo_name;

	unsigned char *packet;
	mapid_pkthdr_t packet_header;

	flist_t *anonfunclist;
	flist_t *anonprocfunclist;
	flist_t *flows;
} mapid_tap;

typedef struct mapidlib_instance {
  
#ifdef WITH_PRIORITIES
  flist_t **flowlist;
#else
  flist_t *flowlist;//=NULL;  //List of flows
#endif	
//  flist_t *flowlist;//=NULL;  //List of flows
  unsigned fcount;	//Number of functions
  pthread_spinlock_t *shm_spinlock; //Pointer to start of shared memory that contains a spinlock
  unsigned long long shm_spinlock_size; //Size of shared memory
  key_t shm_spinlock_key;
  int shm_spinlock_id;
  char shm_spinlock_fname[MAPI_STR_LENGTH];

}mapidlib_instance_t;

typedef int (*mapid_add_function)(mapidlib_instance_t *i, int fd, char *funct, ...);

//Structure used by the to_buffer function
struct mapid_to_buffer {
  key_t buf_key; //Shared memory key for the buffer
  unsigned long read_ptr; //Pointer to the next packet that can be read
  unsigned long write_ptr; //Pointer to where the next packet can be written
  char* buf; //Pointer to buffer
  int cap_length; //Maximum size of a captured packet
  unsigned bufsize;  //Size of buffer
  key_t sem_key; //key of the semaphore used for blocking the clients app.
  int semaphore; //the semaphore ID
};



//General information about the hardware adapter that is being used
//and that various functions might find useful
typedef struct mapid_hw_info {
  unsigned int link_type; // Data-link level type as defined in bpf.h
  unsigned int cap_length; // Maximum packet capture length  
  unsigned long long pkts; //Number of packets read by the device
  unsigned long pkt_drop; // Number of dropped pkts, NOTE: for supported devs.
  char* devtype; //Device type
  short offline; //0 Proper device
                 //1 active offline flow
                 //2 active full speed offline flow
                 //3 finished offline flow
                 //4 if old-fashioned offline
  int devid; //Device ID set by mapid
  int devfd;	//file descriptor for hardware device
  global_function_list_t *gflist; //Global function list
  void *adapterinfo; //Pointer to adapter specific information
} mapid_hw_info_t;


#ifdef WITH_AUTHENTICATION
int mapid_init(mapidlib_instance_t *, mapid_hw_info_t *info);
#else
int mapid_init(mapidlib_instance_t *i);
#endif
void mapid_destroy(mapidlib_instance_t *i);
int mapid_connect(mapidlib_instance_t *i,int fd);
int mapid_add_flow(mapidlib_instance_t *i,int fd,mapid_hw_info_t* hwinfo,void *info);
int mapid_close_flow(mapidlib_instance_t *i,int fd);

int mapid_read_results(mapidlib_instance_t *i,
		       int fd,
		       int fid,
		       mapid_result_t **result);
int  mapid_apply_function(mapidlib_instance_t *i,
			  int fd,
			  char* function,
			  mapiFunctArg *fargs,
			  int flags);
void mapid_process_pkt(mapidlib_instance_t *i,
		       unsigned char* dev_pkt,
		       unsigned char* link_pkt,
		       mapid_pkthdr_t* pkt_head);
int mapid_get_errno(mapidlib_instance_t *i,int fid);
//void mapid_delete_flows(mapidlib_instance_t *i);
int mapid_get_devid(mapidlib_instance_t *i,int fd);
int mapid_load_library(char *lib);
int mapid_get_flow_info(mapidlib_instance_t *i,int fd,mapi_flow_info_t *info);
//void mapid_lock(mapidlib_instance_t *i);
//void mapid_unlock(mapidlib_instance_t *i);

mapid_funct_info_t* mapid_get_flow_functions(mapidlib_instance_t *i,int fd);

int mapid_finished(mapidlib_instance_t *i);

//char* mapid_get_lib_name(int libnumber);

#endif
