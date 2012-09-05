#ifndef MAPI_INTERNAL_H
#define MAPI_INTERNAL_H 1

#include "mapilibhandler.h"

void set_agent();

typedef struct functdescr {
  int fid;
  short result_init;
  mapidflib_function_def_t *def;
  mapidflib_function_t *funct;
  void *data; 
  mapi_results_t *result;
} functdescr_t;

typedef struct shm_result {
  void *ptr; //Pointer to shared data
  int size; //Size of shared data
} shm_result_t;

typedef enum {
  FLOWTYPE_LOCAL,
  FLOWTYPE_REMOTE
} flowtype_t;

typedef struct flowlist_item {
  int fd;
  flowtype_t flowtype;
  void *driver;
  void *flowdescr;
} flowlist_t;

// This feels a little dirty but it works :)
struct flowdrv_globals {
  int *minit;
  int *mapi_lock;
  
  int *local_err;
  int *agent;
  
  flist_t **flowlist;
  int *fd_counter;
  
  void *localdrv;
  void *remotedrv;
  
  int (*get_numflows)();
  int (*incr_numflows)();
  int (*decr_numflows)();
  int (*get_totalflows)();
  int (*incr_totalflows)();
};

// internal use only (mapi_create_flow does not give devtype directly) 
extern char *mapi_get_devtype_of_flow(int id);

#endif
