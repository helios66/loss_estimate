#ifndef _MAPID_H
#define _MAPID_H 1

#include "mapi_local.h"
#include "mapiipc.h"
#include "flist.h"

#define FUNCTION_SHM_TEMPLATE "/tmp/.mapidfunc-shm-XXXXXX"
#define FUNCTION_SHM_PROJECT_ID 'F'
#define FUNCTION_SHM_PERMS 0660
#define FUNCTION_SEM_TEMPLATE "/tmp/.mapidfunc-sem-XXXXXX"
#define FUNCTION_SEM_PROJECT_ID 'S'
#define FUNCTION_SEM_PERMS 0660

/* OR-able options to mapid_apply_function() */
#define APPLY_NORMAL    0x00    /* apply function normally at the tail of the flow */ 
#define APPLY_INTERNAL  0x01    /* apply function at the head of the flow          */
#define APPLY_STDFLIB   0x02    /* fallback directly to stdflib (MAPI_DEVICE_ALL)  */

typedef struct mapid_flow_info {
  enum mapi_flow_status status;
  flist_t *flist; //List of all functions applied to the flow
} mapid_flow_info_t;

typedef struct mapid_funct_info {
  int fid;
  char* name; //Name of function
  char* libname; //Name of library the function belongs to
  char* devtype; //Device type the function is compatible with
  char* argdescr; //Description of arguments
  mapiFunctArg args[FUNCTARGS_BUF_SIZE]; //Arguments passed to the function
  unsigned long long *pkts; //Number of packets that has been processed
  unsigned long long *passed_pkts; //Number of packets that has passed the function
  struct mapid_funct_info *next;
} mapid_funct_info_t;

typedef struct mapid_shm {
  key_t key; // shared memory key
  long buf_size; // size of entire shared memory buffer
  long res_size; //Size of result
  long offset; //Offsett of result in the shared memory buffer  
} mapid_shm_t;

typedef struct mapid_result {
  void *funct_res; //Pointer to function specific result data
  unsigned funct_res_size; //size of result
  mapid_shm_t shm;
  mapid_shm_t shm_spinlock;
} mapid_result_t;

typedef struct global_function_list {
  int lock;
  flist_t *fflist; //List of all flows and and all functions applied to each flow
} global_function_list_t;


#endif
