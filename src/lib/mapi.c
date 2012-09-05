#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/file.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <unistd.h>
#include "mapi.h"
#include "mapi_internal.h"
#include "mapiipc.h"
#include "mapilibhandler.h"
#include "flist.h"
#include "debug.h"
#include "printfstring.h"
#include "mapi_errors.h"

static pthread_once_t initialized = PTHREAD_ONCE_INIT;
static int minit = 0; //Set to 1 when MAPI has been initialized

static int mapi_lock = 0;
static int numflows_lock = 0;  // for numflows and totalflows variables

static int local_err = 0; /* occurence of a mapi.c error, translation of these errors */

static int numflows = 0;  // number of allocated (active) flows
static int totalflows = 0;  // number of flows so far (including closed flows)

static int agent = 0;

extern const errorstruct Errors[];

typedef struct libinfo {
  char* name;
} libinfo_t;

/* main flowlist, manages all local and remote flows */
flist_t *flowlist = NULL;
static int fd_counter = 0; // pre incr and use.

/* drivers for local and remote flows, with following functions */
void *localdrv = NULL;
void *remotedrv = NULL;
struct flowdrv_globals *drvglobals = NULL;

static void *get_driver(const char *dev);
static void *drv_get_funct(void *drv, const char *funct);

//global var access functions
static int get_numflows();
static int incr_numflows();
static int decr_numflows();
static int get_totalflows();
static int incr_totalflows();

// Flow driver prototypes, ref mapi_flowdrv.h
int (*flowdrv_setglobals)(const struct flowdrv_globals *globals);
void (*flowdrv_init)();
int (*flowdrv_connect)(flowlist_t *flow_item);
int (*flowdrv_create_flow)(const char *dev);
char * (*flowdrv_create_offline_device)(const char *path, int format);
int (*flowdrv_start_offline_device)(const char *dev);
int (*flowdrv_delete_offline_device)(char *dev);
int (*flowdrv_close_flow)(flowlist_t *flow_item);
int (*flowdrv_apply_function)(flowlist_t *flow_item, const char *funct, va_list vl);
mapi_results_t * (*flowdrv_read_results)(flowlist_t *flow_item, int fid);
struct mapipkt * (*flowdrv_get_next_pkt)(flowlist_t *flow_item, int fid);
int (*flowdrv_is_connected)(flowlist_t *flow_item, int fid);
int (*flowdrv_get_function_info)(flowlist_t *flow_item, int fid, mapi_function_info_t *info);
int (*flowdrv_get_next_function_info)(int fd, int fid, mapi_function_info_t *info);
int (*flowdrv_get_flow_info)(flowlist_t *flow_item, mapi_flow_info_t *info);
int (*flowdrv_get_next_flow_info)(int fd, mapi_flow_info_t *info);
int (*flowdrv_get_next_device_info)(int devid, mapi_device_info_t *info);
int (*flowdrv_get_device_info)(int devid, mapi_device_info_t *info);
int (*flowdrv_stats)(const char *dev, struct mapi_stat *stats);
char * (*flowdrv_get_devtype_of_flow)(flowlist_t *flow_item);

int (*flowdrv_get_scope_size)(flowlist_t *flow_item); // Only used by DiMAPI

/*
 * Finds the right driver and returns a dlopen handle.
 * dev = the device string given to mapi_create_flow()
 */
void *get_driver(const char *dev)
{
  /* Check if this is a remote device or not and load the appropriate driver */
  if (strchr(dev, ':') != NULL)
  {
    return remotedrv;
  }
  else
  {
    return localdrv;
  }
}

/*
 * Returns a pointer to a function inside a driver
 * drv = pointer to driver
 * funct = name of function
 */
void *drv_get_funct(void *drv, const char *funct)
{
  char *msg= NULL;
  void *my_funct = (void *) dlsym(drv, funct);
  
  if (my_funct == NULL) {
    msg = (char *) dlerror();
    DEBUG_CMD(Debug_Message("ERROR: drv_get_funct: %s", msg));
    dlclose(drv);
    exit(EXIT_FAILURE);
  }

  return my_funct;
}


static void init()
//common initialization function for mapi and dimapi
{

  // set up globals
  if (drvglobals == NULL)
  {
    drvglobals = malloc(sizeof(struct flowdrv_globals));

    drvglobals->minit = &minit;
    drvglobals->mapi_lock = &mapi_lock;
    
    drvglobals->local_err = &local_err;
    drvglobals->agent = &agent;
    
    drvglobals->flowlist = &flowlist;
    drvglobals->fd_counter = &fd_counter;
    
    drvglobals->localdrv = &localdrv;
    drvglobals->remotedrv = &remotedrv;
    
    drvglobals->get_numflows = get_numflows;
    drvglobals->incr_numflows = incr_numflows;
    drvglobals->decr_numflows = decr_numflows;
    drvglobals->get_totalflows = get_totalflows;
    drvglobals->incr_totalflows = incr_totalflows;
  }
  
  // TODO/XXX: read flowdrivers from conf file? can default to libmapi_local/remote.so if no conf is found.
  
  // Load local driver
  localdrv = (void *) dlopen("libmapi_local.so", RTLD_NOW);
  if (localdrv == NULL)
  {
    local_err = 0; // FIXME: Add MAPI_INIT_LOADING_DRIVER
    printf("ERROR: Could not load local driver (libmapi_local.so).\n");
    printf("Aborting...\n");
    exit(1);
  }
  flowdrv_setglobals = drv_get_funct(localdrv, "flowdrv_setglobals");
  if (flowdrv_setglobals == NULL)
  {
    local_err = 0; // FIXME: add error constant
    printf("ERROR: Could not initialize driver.\n");
    printf("Aborting...\n");
    exit(1);
  }
  (*flowdrv_setglobals)(drvglobals);
  
#ifdef DIMAPI
  // Load remote driver
  remotedrv = (void *) dlopen("libmapi_remote.so", RTLD_NOW);
  if (remotedrv == NULL)
  {
    local_err = 0; // FIXME: see previous
    printf("ERROR: Could not load remote (DiMAPI) driver (libmapi_remote.so).\n");
    printf("Aborting...\n"); // XXX: Should we just continue? it does have local loaded.
    exit(1);
  }
  flowdrv_setglobals = drv_get_funct(remotedrv, "flowdrv_setglobals");
  if (flowdrv_setglobals == NULL)
  {
    local_err = 0; // FIXME: add error constant
    printf("ERROR: Could not initialize driver.\n");
    printf("Aborting...\n");
    exit(1);
  }
  (*flowdrv_setglobals)(drvglobals);
#endif
  
  flowdrv_setglobals = NULL;
  // Don't free drvglobals here, that will break offline processing.
  printf("INIT2\n");
  minit = 1;


  flowlist = malloc(sizeof(flist_t));
  flist_init(flowlist);
}

int mapi_connect(int fd)
//Connect to a mapi flow
//fd = flow descriptor
{
  flowlist_t *flow_item;

  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }
  else if (fd <= 0)
  {
   printf("ERROR: Invalid flow descriptor (fd: %d) in mapi_connect\n", fd);
   return -1;
  }

  if ((flow_item = flist_get(flowlist, fd)) == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    local_err = MAPI_INVALID_FLOW;
    return -1;
  }
  
  flowdrv_connect = drv_get_funct(flow_item->driver, "flowdrv_connect");
  return flowdrv_connect(flow_item);
}

int mapi_create_flow(const char *dev)
//Create new flow
//dev=device that should be used
{
  if(dev == NULL)
  {
    printf("ERROR: Wrong device name given (NULL) in mapi_create_flow\n");
    local_err  = MAPI_DEVICE_INFO_ERR;
    return -1;
  }
  
  //  pthread_once(&initialized, (void*)init);
  init();  
  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }

  // XXX: Create flowlist_item here and insert when driver func completes successfully??
  void *driver = get_driver(dev);
  flowdrv_create_flow = drv_get_funct(driver, "flowdrv_create_flow");
  return (*flowdrv_create_flow)(dev);
}

char *mapi_create_offline_device(const char *path, int format)
// Create new offline device
// path = tracefile that should be used
// format = tracefile format constant
{
  pthread_once(&initialized, (void*)init);
  
  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return NULL;
  }
  
  void *driver = localdrv; // only available on local
  flowdrv_create_offline_device = drv_get_funct(driver, "flowdrv_create_offline_device");
  return (*flowdrv_create_offline_device)(path, format);
}

int mapi_start_offline_device(const char *dev)
//Start offline device
//dev = offline device that should be used
{
  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }
  
  void *driver = localdrv; // only available on local
  flowdrv_start_offline_device = drv_get_funct(driver, "flowdrv_start_offline_device");
  return (*flowdrv_start_offline_device)(dev);
}

int mapi_delete_offline_device(char *dev)
// Delete offline device
// dev = offline device that should be deleted
{
  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }
  
  void *driver = localdrv; // only available on local
  flowdrv_delete_offline_device = drv_get_funct(driver, "flowdrv_delete_offline_device");
  return (*flowdrv_delete_offline_device)(dev);
}

int mapi_close_flow(int fd)
{
  flowlist_t *flow_item = NULL;

  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }
  else if (fd <= 0)
  {
    printf("ERROR: Wrong fd (fd: %d) in mapi_close_flow\n", fd);
    return -1;
  }

  if (flowlist && (flow_item = flist_get(flowlist, fd)) == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    local_err = MAPI_INVALID_FLOW;
    return -1;
  }
  else
  {
    flow_item = flist_remove(flowlist,fd);

    flowdrv_close_flow = drv_get_funct(flow_item->driver, "flowdrv_close_flow");
    return (*flowdrv_close_flow)(flow_item);
  }
}

int mapi_apply_function(int fd, const char *funct, ...)
//Apply function to a mapi flow
//fd: flow descriptor
//funct: function to be added
{
  flowlist_t *flow_item = NULL;
  va_list vl;

  printf("%d\n",minit);

  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }
  else if (fd <= 0)
  {
    printf("ERROR: Wrong fd (fd: %d) in mapi_apply_function\n", fd);
    local_err = MAPI_INVALID_FID_FUNCID;
    return -1;
  }
  if (funct == NULL)
  {
    printf("ERROR: NULL function in mapi_apply_function\n");
    local_err = MFUNCT_COULD_NOT_APPLY_FUNCT;
    return -1;
  }
  
  if ((flow_item = flist_get(flowlist, fd)) == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    local_err = MAPI_INVALID_FLOW;
    return -1;
  }
  
  va_start(vl, funct);

  flowdrv_apply_function = drv_get_funct(flow_item->driver, "flowdrv_apply_function");
  return (*flowdrv_apply_function)(flow_item, funct, vl);
}

// old signature: int mapi_read_results(int fd, int fid, void *result)
//Read result from a function
//fd: flow descriptor
//fid: ID of function
mapi_results_t* mapi_read_results(int fd, int fid)
{
  flowlist_t *flow_item;

  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return NULL;
  }
  else if (fd <= 0 || fid <= 0)
  {
    printf("ERROR: Wrong fd (fd: %d) or fid (fid: %d) in mapi_read_results\n", fd, fid);
    local_err = MAPI_INVALID_FLOW;
    return NULL;
  }

  if ((flow_item = flist_get(flowlist, fd)) == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    local_err = MAPI_INVALID_FLOW;
    return NULL;
  }

  flowdrv_read_results = drv_get_funct(flow_item->driver, "flowdrv_read_results");
  return (*flowdrv_read_results)(flow_item, fid);
}

/** \brief Get the next packet from a to_buffer function

	\param fd flow descriptor
	\param fid id of TO_BUFFER function

	\return Reference to next packet, or NULL on error
*/
struct mapipkt *
mapi_get_next_pkt(int fd,int fid) 
{
  flowlist_t *flow_item;

  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return NULL;
  }
  else if (fd <= 0 || fid <= 0 )
  {
    printf("ERROR: Wrong fd (fd: %d) or fid (fid: %d) in mapi_get_next_pkt\n", fd, fid);
    local_err = MAPI_INVALID_FID_FUNCID;
    return NULL;
  }

  if ((flow_item = flist_get(flowlist, fd)) == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    local_err = MAPI_INVALID_FLOW;
    return NULL;
  }
  
  flowdrv_get_next_pkt = drv_get_funct(flow_item->driver, "flowdrv_get_next_pkt");
  return (*flowdrv_get_next_pkt)(flow_item, fid);
}

// XXX: what to do with this? apparently its only for diMAPI
// struct mapipkt* mapi_asynchronous_get_next_pkt(int fd, int fid){


int mapi_loop(int fd, int fid, int cnt, mapi_handler callback)
{

  flowlist_t *flow_item;
  struct mapipkt *pkt;
  int i = 0;
  
  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }
  else if (fd <= 0 || fid <= 0)
  {
    printf("ERROR: Wrong fd (fd: %d) or fid (fid: %d) in mapi_loop\n", fd, fid);
    local_err = MAPI_INVALID_FID_FUNCID;
    return -1;
  }

  if ((flow_item = flist_get(flowlist, fd)) == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    local_err = MAPI_INVALID_FLOW;
    return -1;
  }

  flowdrv_is_connected = drv_get_funct(flow_item->driver, "flowdrv_is_connected");
  if (!(*flowdrv_is_connected)(flow_item, fid))
  {
    printf("ERROR: In mapi_loop always use mapi_connect first\n");
    local_err = MAPI_FLOW_NOT_CONNECTED;
    return -1;
  }

  if (callback == NULL)
  {
    local_err = MFUNCT_INVALID_ARGUMENT_4;
    return -1;
  } 

  flowdrv_get_next_pkt = drv_get_funct(flow_item->driver, "flowdrv_get_next_pkt");

  if (cnt > 0)
  {
    for (i = 0; i < cnt; i++)
    {
      pkt = (*flowdrv_get_next_pkt)(flow_item, fid);
      if (pkt == NULL) return local_err;
      (*callback)(pkt); 
    }
  }
  else
  {
    while(1)
    {
      pkt = (*flowdrv_get_next_pkt)(flow_item, fid);
      if (pkt == NULL) return local_err;
      (*callback)(pkt);
    }
  }
  
  return 0;
}

/*
 * Very simple function. Just reads the last error that was set. 
 */
int mapi_read_error(int* err_no, char* errorstr)
{
  int i = 0;

  if (err_no == NULL && errorstr == NULL)
  {
    return -1;
  }

  if (err_no != NULL) *err_no = local_err;

  if (errorstr != NULL)
  {
    for (; Errors[i].err_no!=0; i++)
    {
      if (Errors[i].err_no == local_err)
      {
        if(strlen(Errors[i].desc) < MAPI_ERRORSTR_LENGTH){
          strncpy(errorstr, Errors[i].desc, MAPI_ERRORSTR_LENGTH); 
        }
        else
        {
          strcpy(errorstr,"Error in mapi_read_error: Error string too long\n");
        }
        
        break;
      }
    }
  }

  local_err = 0;

  return 0;
}

// XXX: why doesnt this just return the mapi_function_info_t pointer or NULL on failure like some other functions??
int mapi_get_function_info(int fd,int fid, mapi_function_info_t *info)
{
  flowlist_t *flow_item;

  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }
  else if (fd <= 0 || fid <= 0)
  {
    printf("ERROR: Wrong fd (fd: %d) or fid (fid: %d) in mapi_get_function_info\n", fd, fid);
    local_err = MAPI_INVALID_FID_FUNCID;
    return -1;
  }
  else if (info == NULL)
  {
     local_err = MFUNCT_INVALID_ARGUMENT_3;
     return -1;
  }

  if ((flow_item = flist_get(flowlist, fd)) == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }
  
  flowdrv_get_function_info = drv_get_funct(flow_item->driver, "flowdrv_get_function_info");
  return (*flowdrv_get_function_info)(flow_item, fid, info);
}

// XXX: see return comment on previous function
int mapi_get_next_function_info(int fd, int fid, mapi_function_info_t *info)
{
  if (fd <= 0 || fid < 0)
  {
    printf("ERROR: Wrong fd (fd: %d) or fid (fid: %d) in mapi_get_next_function_info\n", fd, fid);
    local_err = MAPI_INVALID_FID_FUNCID;
    return -1;
  }
  else if (info == NULL)
  {
    printf("ERROR: NULL argument in mapi_get_next_function_info\n");
    local_err = MFUNCT_INVALID_ARGUMENT_3;
    return -1;
  }

  pthread_once(&initialized, (void*)init);

  flowdrv_get_next_function_info = drv_get_funct(localdrv, "flowdrv_get_next_function_info");
  return (*flowdrv_get_next_function_info)(fd, fid, info);
}

// XXX: see return comment on previous functions
int mapi_get_flow_info(int fd, mapi_flow_info_t *info)
{
  flowlist_t *flow_item;

  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }
  else if (fd <= 0)
  {
    printf("ERROR: Invalid flow descriptor %d in mapi_get_flow_info\n", fd);
    local_err = MAPI_INVALID_FLOW;
    return -1;
  }

  if (info == NULL)
  {
    local_err = MFUNCT_INVALID_ARGUMENT_2;
    return -1;
  }

  if ((flow_item = flist_get(flowlist, fd)) == NULL){
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    local_err = MAPI_INVALID_FLOW;
    return -1;
  }

  flowdrv_get_flow_info = drv_get_funct(flow_item->driver, "flowdrv_get_flow_info");
  return (*flowdrv_get_flow_info)(flow_item, info);
}

// XXX: see return comment on previous functions
int mapi_get_next_flow_info(int fd, mapi_flow_info_t *info)
{
  if (fd < 0)
    fd = 0;

  if (info == NULL)
  {
    local_err = MFUNCT_INVALID_ARGUMENT_2;
    return -1;
  }

  pthread_once(&initialized, (void*)init);

  flowdrv_get_next_flow_info = drv_get_funct(localdrv, "flowdrv_get_next_flow_info");
  return (*flowdrv_get_next_flow_info)(fd, info);
}

extern int mapi_get_libfunct_info(int libnum, int fnum, mapi_libfunct_info_t *info)
{
  int c;
  mapidflib_functionlist_t *functs;

  pthread_once(&initialized, (void*)init);

  flowdrv_init = drv_get_funct(localdrv, "flowdrv_init");
  (*flowdrv_init)();

  functs = mapidflib_get_lib_functions(libnum);

  for (c = 0; c < fnum && functs != NULL; c++) // <-- hmm, subtle hint? :)
    functs = functs->next;

  if (functs == NULL)
    return -1;

  strncpy(info->name, functs->def->name, MAPI_STR_LENGTH);
  strncpy(info->descr, functs->def->descr, MAPI_STR_LENGTH);
  strncpy(info->argdescr, functs->def->argdescr, MAPI_STR_LENGTH);

  return 0;
}

extern int mapi_get_next_libfunct_info(int libnum, int fnum, mapi_libfunct_info_t *info)
{
  int ret;

  if (fnum < 0)
    ret = mapi_get_libfunct_info(libnum, 0, info);
  else
    ret = mapi_get_libfunct_info(libnum, fnum + 1, info);

  return ret;
}

int mapi_get_library_info(int libid, mapi_lib_info_t *info) 
{
  char *name;

  pthread_once(&initialized, (void*)init);

  flowdrv_init = drv_get_funct(localdrv, "flowdrv_init");
  (*flowdrv_init)();

  name = mapidflib_get_lib_name(libid);

  if (name == NULL)
    return -1;

  strncpy(info->libname, name, MAPI_STR_LENGTH);
  info->id = libid;
  info->functs = mapidflib_get_lib_numfuncts(libid);

  return 0;
}


int mapi_get_next_library_info(int libid, mapi_lib_info_t *info) 
{
  int ret;

  if (libid < 0)
    ret = mapi_get_library_info(0, info);
  else
    ret = mapi_get_library_info(libid + 1, info);

  return ret;
}

// XXX: why not return mapi_device_info_t pointer instead of using out param?
int mapi_get_next_device_info(int devid, mapi_device_info_t *info)
{
  if (info == NULL)
  {
    local_err = MFUNCT_INVALID_ARGUMENT_2;
    return -1;
  }

  pthread_once(&initialized, (void*)init);

  flowdrv_get_next_device_info = drv_get_funct(localdrv, "flowdrv_get_next_device_info");
  return (*flowdrv_get_next_device_info)(devid, info);
}

// XXX: see return comment above
int mapi_get_device_info(int devid, mapi_device_info_t *info)
{
  if (info == NULL)
  {
    local_err = MFUNCT_INVALID_ARGUMENT_2;
    return -1;
  }

  pthread_once(&initialized, (void*)init);

  flowdrv_get_device_info = drv_get_funct(localdrv, "flowdrv_get_device_info");
  return (*flowdrv_get_device_info)(devid, info);
}

int mapi_stats(const char *dev, struct mapi_stat *stats)
{
  if (dev == NULL)
  {
    printf("ERROR: Invalid device name given (NULL) in mapi_stats\n");
    local_err  = MAPI_DEVICE_INFO_ERR;
    return -1;
  }
  if (stats == NULL)
  {
    printf("ERROR: stats must have memory allocated first.\n");
    local_err  = MFUNCT_INVALID_ARGUMENT_2;
    return -1;
  }
  
  pthread_once(&initialized, (void*)init);
  
  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return -1;
  }

  void *driver = get_driver(dev);
  flowdrv_stats = drv_get_funct(driver, "flowdrv_stats");
  return (*flowdrv_stats)(dev, stats);
}

// Returns the size of the scope of a flow. (DiMAPI)
int mapi_get_scope_size(int fd)
{
  flowlist_t *flow_item = flist_get(flowlist, fd);

  if (flow_item != NULL)
  {
    switch (flow_item->flowtype)
    {
      case FLOWTYPE_REMOTE:
        flowdrv_get_scope_size = drv_get_funct(flow_item->driver, "flowdrv_get_scope_size");
        return (*flowdrv_get_scope_size)(flow_item);

      case FLOWTYPE_LOCAL:
        return 1;

      default:
        break;
    }
  }

  local_err = MAPI_INVALID_FLOW;
  return -1;
}

// Returns 1 if flow is of remote type. (DiMAPI)
// XXX: Maybe this should be more general and just return the flowtype?
int mapi_is_remote(int fd)
{
  flowlist_t *flow_item = flist_get(flowlist, fd);

  if (flow_item != NULL)
  {
    switch (flow_item->flowtype)
    {
      case FLOWTYPE_REMOTE:
        return 1;

      default:
        return 0;
    }
  }

  local_err = MAPI_INVALID_FLOW;
  return -1;
}

// agent = remote node (dimapi mapicommd)
void set_agent() {
  agent = 1;
}

char *mapi_get_devtype_of_flow(int fd)
{
  flowlist_t *flow_item;
  if (!minit)
  {
    printf("MAPI not initialized! [%s:%d]\n", __FILE__, __LINE__);
    local_err = MAPI_INIT_ERROR;
    return NULL;
  }
  else if (fd <= 0)
  {
    printf("ERROR: Invalid flow descriptor %d in mapi_get_devtype_of_flow\n", fd);
    local_err = MAPI_INVALID_FLOW;
    return NULL;
  }

  if((flow_item = flist_get(flowlist, fd)) == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    local_err = MAPI_INVALID_FLOW;
    return NULL;
  }

  flowdrv_get_devtype_of_flow = drv_get_funct(flow_item->driver, "flowdrv_get_devtype_of_flow");
  return (*flowdrv_get_devtype_of_flow)(flow_item);
}

//global var access functions

int get_numflows() {
  int n;
  while(__sync_lock_test_and_set(&numflows_lock,1));
  n = numflows;
  numflows_lock = 0;
  return n;
}

// increases numflows and returns its new value
int incr_numflows() {
  int n;
  while(__sync_lock_test_and_set(&numflows_lock,1));
  n = ++numflows;
  numflows_lock = 0;
  return n;
}

// decreases numflows and returns its new value
int decr_numflows() {
  int n;
  while(__sync_lock_test_and_set(&numflows_lock,1));
  n = --numflows;
  numflows_lock = 0;
  return n;
}

int get_totalflows() {
  int n;
  while(__sync_lock_test_and_set(&numflows_lock,1));
  n = totalflows;
  numflows_lock = 0;
  return n;
}

// increases totalflows and returns its new value
int incr_totalflows() {
  int n;
  while(__sync_lock_test_and_set(&numflows_lock,1));
  n = ++totalflows;
  numflows_lock = 0;
  return n;
}

