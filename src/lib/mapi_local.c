#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/file.h>
#include <fcntl.h>
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
#include <sys/socket.h>
#include <sys/un.h>
#include "mapi.h"
#include "mapi_internal.h"
#include "mapiipc.h"
#include "mapilibhandler.h"
#include "flist.h"
#include "debug.h"
#include "printfstring.h"
#include "mapi_errors.h"
#include "mapi_flowdrv.h"
#include "mapi_local.h"

#define HAVE_MSGHDR_MSG_CONTROL 1 // Why do we have this ?

// TODO: clean up unneeded header files.

static pthread_once_t mapi_is_initialized = PTHREAD_ONCE_INIT;
static int *minit; //Set to 1 when MAPI has been initialized
static boolean_t globals_set = 0;

static int *mapi_lock;

static int *local_err; /* occurence of a mapi.c error, translation of these errors */

static int offline_devices;
static int *agent;

static flist_t **flowlist; // defined in mapi.c
static int *fd_counter; // pre incr and use.
static void **localdrv; // XXX: make a more dynamic system?

// IPC socket
static int sock;
static int mapidaddr_len;
static struct sockaddr_un mapidaddr;
static char *mapidsocket;
static char *mapidsocketglobal;

/*
 * Function declarations 
 */
static int default_read_result_init(flowdescr_t *flow, functdescr_t *f, void *data);
int get_results_info(flowdescr_t *flow, functdescr_t *f);

static int send_fd(int *fds, int numfd);

//global var access functions
int (*get_numflows)();
int (*incr_numflows)();
int (*decr_numflows)();
int (*get_totalflows)();
int (*incr_totalflows)();

void flowdrv_setglobals(const struct flowdrv_globals *globals) {
  minit = globals->minit;
  mapi_lock = globals->mapi_lock;
  
  local_err = globals->local_err;
  agent = globals->agent;
  
  flowlist = globals->flowlist;
  fd_counter = globals->fd_counter;
  
  localdrv = globals->localdrv;
  
  get_numflows = globals->get_numflows;
  incr_numflows = globals->incr_numflows;
  decr_numflows = globals->decr_numflows;
  get_totalflows = globals->get_totalflows;
  incr_totalflows = globals->incr_totalflows;
  
  globals_set = 1;
}

//Initializes MAPI - called only once by pthread_once()
void mapi_init()
{
  if (!globals_set)
  {
    fprintf(stderr, "\nERROR: driver not initialized!\n");
    return;
  }
  struct mapiipcbuf qbuf;
  char libpath[4096], *str, *s;
  *minit = 1;
  char *mapidsocket, *mapidsocketglobal;

  char errstr[512];

  mapidsocket = printf_string(MAPIDSOCKHOME, getenv("HOME"));
  mapidsocketglobal = strdup(MAPIDSOCKGLOBAL);
  mapiipc_set_socket_names(mapidsocket, mapidsocketglobal);

  if (mapiipc_client_init() == -1)
  {
    *local_err = MCOM_INIT_SOCKET_ERROR;
    *minit=0;
    fprintf(stderr, "\n--------------------------------------------------------\n");
    fprintf(stderr, "WARNING: mapid may not be running at the given interface\n");
    fprintf(stderr,"--------------------------------------------------------\n");
  }

  offline_devices = 0;
  
  //Get libpath from mapid
  qbuf.mtype = 1;
  qbuf.cmd = GET_LIBPATH;
  qbuf.fd = getpid();
  qbuf.pid = getpid();
  
  while(__sync_lock_test_and_set(mapi_lock,1));
  
 if (mapiipc_write((struct mapiipcbuf*)&qbuf))
    *local_err = MCOM_SOCKET_ERROR;
 if (mapiipc_read((struct mapiipcbuf*)&qbuf))
    *local_err = MCOM_SOCKET_ERROR;
  
  if (*local_err)
  {
    mapi_read_error(local_err, errstr);
    fprintf(stderr, "ERROR: %d: %s \n", *local_err, errstr);
  }
  
  *mapi_lock = 0;
  
  switch(qbuf.cmd)
  {
    case GET_LIBPATH_ACK:
      strncpy(libpath, (char *)qbuf.data, 4096);
      break;
    
    default:
      /* MAPI_ERROR_GETTING_LIBPATH */
      return;
  }
  printf("libpath=%s\n", libpath);

  //get libs from mapid
  qbuf.mtype = 1;
  qbuf.cmd = GET_LIBS;
  qbuf.fd = getpid();
  qbuf.pid = getpid();
  
  while(__sync_lock_test_and_set(mapi_lock,1));
  
  if (mapiipc_write((struct mapiipcbuf*)&qbuf))
    *local_err = MCOM_SOCKET_ERROR;
  if (mapiipc_read((struct mapiipcbuf*)&qbuf))
    *local_err = MCOM_SOCKET_ERROR;
    
  if (*local_err)
  {
    mapi_read_error(local_err, errstr);
    fprintf(stderr, "ERROR: %d: %s \n", *local_err, errstr);
  }
  
  *mapi_lock = 0;
  
  switch(qbuf.cmd)
  {
    case GET_LIBS_ACK:
      break;
    
    default:
      /* MAPI_ERROR_GETTING_LIBS */
      return; 
  }

  //Load function libraries
  str = (char *)qbuf.data;
  while((s = strchr(str, ':')) != NULL)
  {
    *s = '\0';
    mapilh_load_library(libpath, str);
    str=s+1;
  }

  mapilh_load_library(libpath, str);
  return;
}

void flowdrv_init()
{
  pthread_once(&mapi_is_initialized, (void*)mapi_init);
}

int flowdrv_connect(flowlist_t *flow_item)
//Connect to a mapi flow
//fd = flow descriptor
{
  struct mapiipcbuf qbuf;
  flowdescr_t *flow;
  
  flow = (flowdescr_t *) flow_item->flowdescr;

  qbuf.mtype = 1;
  qbuf.cmd = CONNECT;
  qbuf.fd = flow->fd;
  qbuf.pid = getpid();
  
  while(__sync_lock_test_and_set(mapi_lock,1));
  
  if (mapiipc_write((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }
  
  *mapi_lock = 0;
  
  switch(qbuf.cmd)
  {
    case CONNECT_ACK:
      flow->is_connected = 1;
      return 0;
    case ERROR_ACK:
      *local_err = qbuf.remote_errorcode;
      return -1;
    default:
      *local_err = MCOM_UNKNOWN_ERROR;
      return -1;
  }  
}

int flowdrv_create_flow(const char *dev)
//Create new flow
//dev = device that should be used
{
  struct mapiipcbuf qbuf;
  flowdescr_t *flow, *tmpflow;

  pthread_once(&mapi_is_initialized, (void*)mapi_init);
  
  while(__sync_lock_test_and_set(mapi_lock,1));

  if (((*get_numflows)() == 0) && ((*get_totalflows)() > 0) && *minit){ // socket has been closed, re-create it
    if(mapiipc_client_init() == -1) {
      *local_err = MCOM_INIT_SOCKET_ERROR;
      *mapi_lock = 0;
      return -1;
    }
    (*incr_numflows)();
  }
  else 
    (*incr_numflows)();
  
  *mapi_lock = 0;

  strncpy((char *)qbuf.data,dev,DATA_SIZE);

  qbuf.mtype = 1;
  qbuf.cmd = CREATE_FLOW;
  qbuf.fd = getpid();
  qbuf.pid = getpid();
  
  while(__sync_lock_test_and_set(mapi_lock,1));

  if (mapiipc_write((struct mapiipcbuf*)&qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    (*decr_numflows)();
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*)&qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    (*decr_numflows)();
    return -1;
  }
  *mapi_lock = 0;
  switch(qbuf.cmd)
  {
    case CREATE_FLOW_ACK:
      tmpflow = flist_get(*flowlist, qbuf.fd);
      if (tmpflow != NULL) 
      {
        printf("ERROR: Mapid gave us a fd (%d) which already exist in our lists, exiting [%s:%d]\n",
            qbuf.fd, __FILE__, __LINE__);
        (*decr_numflows)();
        return -1;
      }
      flow = malloc(sizeof(flowdescr_t));
      if (flow == NULL)
      {
        printf("ERROR: Out of memory [%s:%d]\n", __FILE__, __LINE__);
        (*decr_numflows)();
        return -1;
      }
      flow->fd = qbuf.fd;
      flow->devtype = (char *) malloc(strlen((char *)qbuf.data) + 1);
      flow->flist = malloc(sizeof(flist_t));

      flow->shm_base = NULL;
      flow->shm_spinlock = NULL;
      flow->file = -1;  // in case of online flow, assigned to -1
      flow->is_connected = 0;
      flow->numfd = 0;  // initialize number of open file descriptors to zero
      flist_init(flow->flist);
      strcpy(flow->devtype, (char *)qbuf.data);
      
      flowlist_t *flow_item = malloc(sizeof(flowlist_t));
      if (flow_item == NULL)
      {
        printf("ERROR: Out of memory [%s:%d]\n", __FILE__, __LINE__);
        (*decr_numflows)();
        return -1;
      }
      
      while(__sync_lock_test_and_set(mapi_lock,1));
      
      flow_item->fd = ++(*fd_counter);
      flow_item->flowtype = FLOWTYPE_LOCAL;
      flow_item->driver = *localdrv; // get_driver ?
      flow_item->flowdescr = flow;
      
      flist_append(*flowlist, *fd_counter, flow_item);
      (*incr_totalflows)();
      
      *mapi_lock = 0;
      
      return *fd_counter;
      
    /* should probably have a separate error message for ERROR_ACK? */
    case ERROR_ACK:
      (*decr_numflows)();
      *local_err = qbuf.remote_errorcode;
      return -1;
    default:
      (*decr_numflows)();
      *local_err = MCOM_UNKNOWN_ERROR;
      return -1;
  }
}

char *flowdrv_create_offline_device(const char *path, int format)
// Create new offline device
// path = tracefile that should be used
// format = tracefile format constant
{
  struct mapiipcbuf qbuf;
  int file;

  char *mapidsocket, *mapidsocketglobal;

  mapidsocket = printf_string(MAPIDSOCKHOME, getenv("HOME"));
  mapidsocketglobal = strdup(MAPIDSOCKGLOBAL);
  mapiipc_set_socket_names(mapidsocket, mapidsocketglobal);

  pthread_once(&mapi_is_initialized, (void*)mapi_init);

  //Check to see if file can be opened
  if (path == NULL){
    printf("ERROR: NULL path in flowdrv_create_offline_device\n");
    return NULL;
  }
  else if ((file = open(path,O_LARGEFILE)) == -1) {
    *local_err = MAPI_ERROR_FILE;
    return NULL;
  }

  while(__sync_lock_test_and_set(mapi_lock,1));
  if (((*get_numflows)() == 0) && ((*get_totalflows)() > 0) && *minit) { // socket has been closed, re-create it
    if (mapiipc_client_init()<0) {
      *mapi_lock = 0;
      *local_err = MCOM_INIT_SOCKET_ERROR;
      return NULL;
    }
  }
  *mapi_lock = 0;

  qbuf.mtype = 1;
  qbuf.cmd = CREATE_OFFLINE_DEVICE;
  qbuf.fd = getpid();
  qbuf.pid = getpid();
  qbuf.fid = format;
  strncpy((char *)qbuf.data, path, DATA_SIZE);
  
  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;	  
    *local_err = MCOM_SOCKET_ERROR;
    return NULL;
  }
  if (mapiipc_read((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;
    *local_err = MCOM_SOCKET_ERROR;
    return NULL;
  }
  
  if(qbuf.cmd == SEND_FD)
  {
    if(mapiipc_send_fd(file) == -1)
    {
      *local_err = MAPI_ERROR_SEND_FD;
      *mapi_lock = 0;
      return NULL;      
    }
  }
  else
  {
    *local_err = MAPI_ERROR_SEND_FD;
    *mapi_lock = 0;
    return NULL;
  }

  if (mapiipc_read((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;
    *local_err = MCOM_SOCKET_ERROR;
    return NULL;
  }
  *mapi_lock = 0;
  
  switch(qbuf.cmd)
  {
    case CREATE_OFFLINE_DEVICE_ACK:
      offline_devices++;
      return strdup((char *)qbuf.data);
    case ERROR_ACK:
      *local_err = qbuf.remote_errorcode;
      return NULL;
    default:
      *local_err = MCOM_UNKNOWN_ERROR;
      return NULL;
  }
}

int flowdrv_start_offline_device(const char *dev)
//Start offline device
//dev = offline device that should be used
{
  struct mapiipcbuf qbuf;

  pthread_once(&mapi_is_initialized, (void*)mapi_init);

  if (dev == NULL) {
    printf("ERROR: NULL device in flowdrv_start_offline_device\n");
    return -1;
  }
  while(__sync_lock_test_and_set(mapi_lock,1));
  if (((*get_numflows)() == 0) && ((*get_totalflows)() > 0) && *minit) { // socket has been closed, re-create it
    if (mapiipc_client_init()<0) {
      *mapi_lock = 0;
      *local_err = MCOM_INIT_SOCKET_ERROR;
      return -1;
    }
  }
  *mapi_lock = 0;

  qbuf.mtype = 1;
  qbuf.cmd = START_OFFLINE_DEVICE;
  qbuf.fd = getpid();
  qbuf.pid = getpid();

  strncpy((char *) qbuf.data, dev, DATA_SIZE);

  qbuf.fid = 0;
  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;	  
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }
  *mapi_lock = 0;
  switch(qbuf.cmd)
  {
    case START_OFFLINE_DEVICE_ACK:
      return 0;
    case ERROR_ACK:
      *local_err = qbuf.remote_errorcode;
      return -1;
    default:
      *local_err = MCOM_UNKNOWN_ERROR;
      return -1;
  }
}

int flowdrv_delete_offline_device(char *dev)
// Delete offline device
// dev = offline device that should be deleted
{
  struct mapiipcbuf qbuf;

  pthread_once(&mapi_is_initialized, (void*)mapi_init);

  if (dev == NULL){
    printf("ERROR: NULL device in flowdrv_delete_offline_device\n");
    return -1;
  }

  qbuf.mtype = 1;
  qbuf.cmd = DELETE_OFFLINE_DEVICE;
  qbuf.fd = getpid();
  qbuf.pid = getpid();

  strncpy((char *) qbuf.data, dev, DATA_SIZE);

  free(dev);
  qbuf.fid = 0;
  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }

  *mapi_lock = 0;
  switch(qbuf.cmd)
  {
    case DELETE_OFFLINE_DEVICE_ACK:
      while(__sync_lock_test_and_set(mapi_lock,1));
      if(((*get_numflows)() == 0) && --offline_devices == 0)
        mapiipc_client_close();
      *mapi_lock = 0;
      return 0;
    case ERROR_ACK:
      *local_err = qbuf.remote_errorcode;
      return -1;
    default:
      *local_err = MCOM_UNKNOWN_ERROR;
      return -1;
  }
}

int flowdrv_close_flow(flowlist_t *flow_item) 
{
  functdescr_t *f = NULL;
  flowdescr_t *flow = (flowdescr_t *) flow_item->flowdescr;
  struct mapiipcbuf qbuf;

  //Delete functions applied first, before mapid is notified.
  while(__sync_lock_test_and_set(mapi_lock,1));

  while((f = flist_pop_first(flow->flist)) != NULL)
  {
    if(f->def->client_cleanup!=NULL && f->funct->instance->status==MAPIFUNC_INIT){
      f->def->client_cleanup(f->funct->instance);
    }

    if(f->result != NULL)
    {
      free(f->result->res);
      free(f->result);
    }
    free(f->funct->instance);
    free(f->funct);
    free(f->data);
    free(f);
  }
  *mapi_lock = 0;

  qbuf.mtype = 1;
  qbuf.cmd = CLOSE_FLOW;
  qbuf.fd = flow_item->fd;
  qbuf.fid = getpid();
  qbuf.pid = getpid();
  
  while(__sync_lock_test_and_set(mapi_lock,1));
  
  if (mapiipc_write((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*)&qbuf) < 0)
  {
    *mapi_lock = 0;
    return -1;
  }
  *mapi_lock = 0;
  
  switch(qbuf.cmd)
  {
    case CLOSE_FLOW_ACK:
      // if this is the last one, release socket resources
      // resources released ~20 lines down, regardless of this switch. (mapiipc_client_close())
      break;
    case ERROR_ACK:
      *local_err = MCOM_ERROR_ACK;
      break;
    default:
      *local_err = MCOM_UNKNOWN_ERROR;
      break;
  }

  //Detach shared mem
  if (flow->shm_base != NULL)
  {
    if (shmdt(flow->shm_base) < 0)
    {
      printf("WARNING: Could not detach shared mem (%s) [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
    }
  }
  
  /* subtract, the flow should be closed either due to an error or
   * explicitly in this function. so numflows is really number of allocated
   * flows...
   */
  while(__sync_lock_test_and_set(mapi_lock,1));
  if (((*decr_numflows)() == 0) && offline_devices == 0)
    mapiipc_client_close();
  *mapi_lock = 0;

  //Free flow resources
  
  int i;    // close opened file descriptors
  for (i = 0; i < flow->numfd; i++)
    close(flow->fds[i]);

  if (flow->file != -1)    // close file descriptor in case of offline flow
    close(flow->file);

  free(flow->devtype);
  free(flow->flist);
  free(flow);
  
  free(flow_item);
  
  return 0;
}

//XXX Why send_fd returns 0 on error whereas every other function 
//return -1 on error?
int send_fd(int *fds, int num) {
  int c;
  struct mapiipcbuf qbuf;

  for(c = 0; c < num; c++)
  {
    if (mapiipc_read((struct mapiipcbuf*)&qbuf) < 0)
    {
      *local_err = MCOM_SOCKET_ERROR;
      return 0; 
    }
    if (qbuf.cmd != SEND_FD)
      return 0;
    if (mapiipc_send_fd(fds[c]) == -1)
      return 0;
  }
  return 1;
}

int flowdrv_apply_function(flowlist_t *flow_item, const char *funct, va_list vl) 
//Apply function to a mapi flow
//fd: flow descriptor
//funct: function to be added
{

  struct mapiipcbuf qbuf = {-1, -1, -1, "", -1, -1, -1, 0, "", "", -1};   // need initialization

  int numfd = 0, tmp, un_id = 0;
  unsigned long long ltmp;
  char ctmp, *argdescr_ptr, *filename, *temp, *tmp_fname;
  char *fids;
  unsigned char* args;    //in case read from a buffer instead of va_list
  mapidflib_function_def_t *fdef;
  functdescr_t *f;
  mapiFunctArg *pos;
  flowdescr_t *flow = (flowdescr_t *) flow_item->flowdescr;

  if (flow->is_connected)
  {
    printf("ERROR: Can not apply function %s on an already connected flow\n", funct);
    *local_err = MFUNCT_COULD_NOT_APPLY_FUNCT;
    return -1;
  }

  //Get information about function
  fdef = mapilh_get_function_def(funct, flow->devtype);

  if (fdef == NULL)
  {
    printf("ERROR: Could not find/match function %s [%s:%d]\n", funct, __FILE__, __LINE__);
    *local_err = MAPI_FUNCTION_NOT_FOUND;
    return -1;
  }

  pos = qbuf.data;  // point to start of arguments buffer

  if (*agent == 1)
  {
    args = va_arg(vl, unsigned char*);
  }

  // parse function arguments
  if (strncmp(fdef->argdescr, "", 1)) // there are some args
  {
    argdescr_ptr = fdef->argdescr;
    while (strlen(argdescr_ptr) > 0)
    {
      switch (*argdescr_ptr)
      {
        case 's':
          if (*agent == 0)
            temp = va_arg(vl, char*);
          else
          {
            temp = (char*)args;
            args += strlen(temp) + 1;
          }
          addarg(&pos, temp, STRING);
          break;

        case 'S':
          if (*agent == 0)
            fids = va_arg(vl, char *);
          else
          {
            fids = (char *)args;
            args += strlen(fids) + 1;
          }
          addarg(&pos, fids, STRING);
          break;
        case 'i':
          if (*agent == 0)
            tmp = va_arg(vl, int);
          else
          {
            memcpy(&tmp, args, sizeof(int));
            args += sizeof(int);
          }
          addarg(&pos, &tmp, INT);
          break;

        case 'r':
          if (*agent == 0)
            tmp = va_arg(vl, int);
          else
          {
            memcpy(&tmp, args, sizeof(int));
            args += sizeof(int);
          }
          addarg(&pos, &tmp, INT);
          break;

        case 'f':
          if (*agent == 0)
            tmp = va_arg(vl, int);
          else
          {
            memcpy(&tmp, args, sizeof(int));
            args += sizeof(int);
          }
          addarg(&pos, &tmp, INT);
          break;

        case 'c':
          if (*agent == 0)
            ctmp = va_arg(vl, int); //`char' is promoted to `int' when passed through `...'
          else
          {
            memcpy(&ctmp, args, sizeof(char));
            args += sizeof(char);
          }
          addarg(&pos, &ctmp, CHAR);
          break;

        case 'l':
          if (*agent == 0)
            ltmp = va_arg(vl, unsigned long long);
          else
          {
            memcpy(&ltmp, args, sizeof(unsigned long long));
            args += sizeof(unsigned long long);
          }
          addarg(&pos, &ltmp, UNSIGNED_LONG_LONG);
          break;

        case 'w':
          //Open file for writing
          if (*agent == 0)
            filename = va_arg(vl, char*);
          else
          {
            filename = (char*)args;
            args += strlen(filename) + 1;
          }
          
          // XXX: should this be combined with if/else above? can agent be less than 0 or bigger than 1 ?
          if (*agent == 1)
          {
            tmp = open(filename, O_WRONLY|O_TRUNC|O_CREAT|O_EXCL|O_LARGEFILE,S_IRUSR|S_IWUSR);
            while (tmp == -1 && errno == EEXIST)
            {
              asprintf(&tmp_fname, "%s-%d", filename, un_id++);
              tmp = open(tmp_fname, O_WRONLY|O_TRUNC|O_CREAT|O_EXCL|O_LARGEFILE,S_IRUSR|S_IWUSR);
              free(tmp_fname);
            }
          }
          else
          {
            tmp = open(filename,O_WRONLY|O_TRUNC|O_CREAT|O_LARGEFILE,S_IRUSR|S_IWUSR);
          }
          
          if (tmp == -1)
          {
            printf("ERROR: Can not create file: %s [%s:%d]\n", filename, __FILE__, __LINE__);
            *local_err = MAPI_ERROR_FILE;
            return -1;
          }
          printf("Created file %s for writing\n", filename);
          
          flow->fds[flow->numfd++] = tmp;
          numfd++;
          addarg(&pos, &tmp, INT);
          break;

        default:
          *local_err = MFUNCT_INVALID_ARGUMENT_DESCRIPTOR;
          printf("ERROR: Illegal argument descriptor %c [%s:%d]\n", *argdescr_ptr, __FILE__, __LINE__);
          return -1;
      }

      argdescr_ptr++; // move to the next arg
    }
  }

  va_end(vl);

  qbuf.mtype = 1;
  qbuf.cmd = APPLY_FUNCTION;
  qbuf.fd = flow->fd;

  qbuf.pid = getpid();
  strncpy(qbuf.function, funct, FUNCT_NAME_LENGTH);
  strncpy((char *)qbuf.argdescr, fdef->argdescr, ARG_LENGTH);  
  
  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  if (!send_fd(flow->fds, numfd))
  {
    *local_err = MAPI_ERROR_SEND_FD;
    *mapi_lock = 0;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*) &qbuf) < 0)
  {
    *mapi_lock = 0;
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }
  *mapi_lock = 0;

  switch (qbuf.cmd)
  {
    case APPLY_FUNCTION_ACK:
      break;
    case ERROR_ACK:
      *local_err = qbuf.remote_errorcode;
      return -1;
    default:
      *local_err = MCOM_UNKNOWN_ERROR;
      return -1;
    }
  
  fdef = mapilh_get_function_def(funct, qbuf.function);

  f = malloc(sizeof(functdescr_t));
  f->fid = qbuf.fid;
  f->def = fdef;
  f->result_init = 0;
  f->data = NULL;
  f->result = NULL;
  
  f->funct = malloc(sizeof(mapidflib_function_t));
  f->funct->fd = flow->fd;

  f->funct->fid = qbuf.fid;
  f->funct->instance = malloc(sizeof(mapidflib_function_instance_t));

  f->funct->instance->status = MAPIFUNC_UNINIT;
  f->funct->instance->hwinfo = NULL;
  f->funct->instance->result.data = NULL;
  f->funct->instance->result.data_size = 0;
  f->funct->instance->result.info.funct_res_size = 0;
  f->funct->instance->result.info.shm.res_size = 0;
  f->funct->instance->result.info.shm.buf_size = 0;
  f->funct->instance->internal_data = NULL;
  memcpy(f->funct->instance->args, qbuf.data, FUNCTARGS_BUF_SIZE);

  flist_append(flow->flist, qbuf.fid, f);

  return qbuf.fid;
}

int _request_result(flowdescr_t *flow, functdescr_t *f, struct mapiipcbuf *qbuf)
{
  qbuf->mtype = 1;
  qbuf->cmd = READ_RESULT;
  qbuf->fd = flow->fd;
  qbuf->fid = f->fid;

  qbuf->pid = getpid();

  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write(qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  if (mapiipc_read(qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  *mapi_lock = 0;
  
  switch (qbuf->cmd)
  {
    case READ_RESULT_ACK:
      break;
    case ERROR_ACK:
      *local_err = qbuf->remote_errorcode;
      return -1;
    default:
      *local_err = MCOM_UNKNOWN_ERROR;
      return -1;
  }

  return 0;
}

int get_results_info(flowdescr_t *flow, functdescr_t *f)
{
  struct mapiipcbuf qbuf;
  
  if (flow == NULL)
  {
    printf("ERROR: Invalid flow (NULL) [%s:%d]\n", __FILE__, __LINE__);
    *local_err = MAPI_INVALID_FLOW;
    return -1;
  }

  if (_request_result(flow, f, &qbuf) != 0)
    return -1;

  default_read_result_init(flow, f, &qbuf.data);
  if (f->def->client_init != NULL)
  {
    int func_err = f->def->client_init(f->funct->instance, &qbuf.data);
    if (func_err != 0)
    {
      *local_err = func_err;
      return -1;
    }
    f->funct->instance->status = MAPIFUNC_INIT;
  }

  f->result_init = 1;
  return 0;
}

// old signature: int mapi_read_results(int fd, int fid, void *result)
//Read result from a function
//fd: flow descriptor
//fid: ID of function
mapi_results_t *flowdrv_read_results(flowlist_t *flow_item, int fid)
{
  flowdescr_t *flow = (flowdescr_t *) flow_item->flowdescr;
  functdescr_t *f;
  mapi_result_t res;
  struct timeval tv; /*used for timestamping results when produced */

  if (!flow->is_connected)
  {
    printf("ERROR: In mapi_read_results always use mapi_connect first\n");
    *local_err = MAPI_FLOW_NOT_CONNECTED;
    return NULL;
  }

  f = flist_get(flow->flist, fid);

  if (f != NULL)
  {
    if(!f->result_init) 
      if (get_results_info(flow, f) != 0)
        return NULL;

    if(f->def->client_init == NULL)
    {
      if(f->data == NULL)
        return(0);
      else    // FIXME in case of reconnection
      {
        if (f->def->restype == MAPIRES_IPC)
        {
          struct mapiipcbuf qbuf;
          void *data = (char *) &qbuf.data + 2 * sizeof(mapid_shm_t); // get to the actual data

          if (_request_result(flow, f, &qbuf) != 0)
          {
            *local_err = MCOM_UNKNOWN_ERROR;
            return NULL;
          }
          memcpy(f->result->res, data, f->funct->instance->result.data_size);

        }
        else    // MAPIRES_SHM
        {
          pthread_spin_lock(flow->shm_spinlock);
          memcpy(f->result->res, ((shm_result_t*)f->data)->ptr, ((shm_result_t*)f->data)->size);
          pthread_spin_unlock(flow->shm_spinlock);
        }

        gettimeofday(&tv, NULL);
        f->result->ts = (unsigned long long)tv.tv_sec * 1000000 + tv.tv_usec;
        f->result->size = ((shm_result_t*)f->data)->size;

        return f->result;
      }
    }
    else 
    {
      int func_err = f->def->client_read_result(f->funct->instance, &res);
      if (func_err != 0) 
      {
        *local_err = func_err;
        return NULL;
      }

      if (res.res == NULL)
      {
        f->result->res = NULL;
      }
      else
      {
        memcpy(f->result->res, res.res, res.size);
      }
      
      gettimeofday(&tv, NULL);
      f->result->ts = (unsigned long long)tv.tv_sec * 1000000 + tv.tv_usec;;
      f->result->size = res.size;

      return f->result;
    }
  }
  else
  {
    *local_err = MAPI_INVALID_FID_FUNCID;
    return NULL; 
  }

  return NULL;      
}

/** \brief Get the next packet from a to_buffer function

	\param fd flow descriptor
	\param fid id of TO_BUFFER function

	\return Reference to next packet, or NULL on error
*/
struct mapipkt *
flowdrv_get_next_pkt(flowlist_t *flow_item, int fid) 
{
  flowdescr_t *flow;
  functdescr_t *f;
  mapi_result_t res;
  int func_err;

  flow = (flowdescr_t *)flow_item->flowdescr;
  
  if (!flow->is_connected)
  {
    printf("ERROR: In flowdrv_get_next_pkt always use flowdrv_connect first\n");
    *local_err = MAPI_FLOW_NOT_CONNECTED;
    return NULL;
  }
  
  if ((f = flist_get(flow->flist, fid)) == NULL)
  {
    *local_err = MAPI_INVALID_FID_FUNCID;
    return NULL;
  }
  
  // This should be attaching shared memory segment with results
  if(!f->result_init)
  {
    if (get_results_info(flow, f) != 0)
    {
      printf("ERROR: Missing error message [%s:%d]\n", __FILE__, __LINE__);
      return NULL;
    }
  }
  
  if (f->def->client_read_result == NULL)
  {
    printf("ERROR: Missing error message [%s:%d]\n", __FILE__, __LINE__);
    return NULL;
  }

  func_err = f->def->client_read_result(f->funct->instance, &res);

  if (func_err != 0)
  {
    *local_err = func_err;
    return NULL;
  }
  
  return res.res;
}

int flowdrv_is_connected(flowlist_t *flow_item)
{
  flowdescr_t* flow;
  
  if (flow_item->flowdescr == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", flow_item->fd, __FILE__, __LINE__);
    *local_err = MAPI_INVALID_FLOW;
    return -1;
  }
  
  flow = (flowdescr_t *)flow_item->flowdescr;
  
  return flow->is_connected;
}

int
default_read_result_init(flowdescr_t *flow, functdescr_t* f, void* data)
{
  mapid_shm_t *shm = data;
  mapid_shm_t *shm_spinlock = (mapid_shm_t*)((char*)data + sizeof(mapid_shm_t));

  int id;

  if (flow == NULL)
  {
    printf("ERROR: Invalid flow (NULL) [%s:%d]\n", __FILE__, __LINE__);
    *local_err = MAPI_INVALID_FLOW;
    return -1;
  }

  if (!flow->shm_base || flow->shm_base == (void *) -1)
  {
    //Get pointer to shared memory
    id = shmget(shm->key, shm->buf_size, 660);
    if (id < 0)
    {
      printf("ERROR: Shared memory error [%s:%d]\n", __FILE__, __LINE__);
      *local_err = MAPI_SHM_ERR;
      return -1;
    }

    if ((flow->shm_base = shmat(id, NULL, FUNCTION_SHM_PERMS)) == (void *) -1)
    {
      *local_err = MAPI_SHM_ERR;
      return -1;
    }
  }

  if (!flow->shm_spinlock || flow->shm_spinlock == (void *) -1)
  {
    //Get pointer to shared spinlock memory
    id = shmget(shm_spinlock->key, shm_spinlock->buf_size, 660);
    if (id < 0)
    {
      printf("ERROR: Shared memory error [%s:%d]\n", __FILE__, __LINE__);
      *local_err = MAPI_SHM_ERR;
      return -1;
    }

    if ((flow->shm_spinlock = shmat(id, NULL, FUNCTION_SHM_PERMS)) == (void *) -1)
    {
      *local_err = MAPI_SHM_ERR;
      return -1;
    }
  }

  f->data = malloc(sizeof(shm_result_t));
  ((shm_result_t*)f->data)->ptr = flow->shm_base + shm->offset;
  ((shm_result_t*)f->data)->size = shm->res_size;

  //Attach result to instance
  f->funct->instance->result.data = flow->shm_base + shm->offset;
  f->funct->instance->result.data_size = shm->res_size;

  f->result = (mapi_results_t*) malloc(sizeof(mapi_results_t));
  f->result->res = (void *) malloc(((shm_result_t*)f->data)->size);

  return 0;
}

int flowdrv_get_function_info(flowlist_t *flow_item, int fid, mapi_function_info_t *info)
{
  struct mapiipcbuf qbuf;
  flowdescr_t* flow;
  
  flow = (flowdescr_t *) flow_item->flowdescr;

  qbuf.mtype = 1;
  qbuf.cmd = GET_FUNCTION_INFO;
  qbuf.fd = flow->fd;
  qbuf.fid = fid;

  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  *mapi_lock = 0;

  if(qbuf.cmd == GET_FUNCTION_INFO_ACK)
  {
    memcpy(info, qbuf.data, sizeof(mapi_function_info_t));
    info->result_size = mapilh_get_function_def(info->name, info->devtype)->shm_size;
    return 0;
  }
  else
  {
    *local_err = MAPI_FUNCTION_INFO_ERR;
    return -1;
  }
}

int flowdrv_get_next_function_info(int fd, int fid, mapi_function_info_t *info)
{
  struct mapiipcbuf qbuf;

  pthread_once(&mapi_is_initialized, (void*)mapi_init);

  qbuf.mtype = 1;
  qbuf.cmd = GET_NEXT_FUNCTION_INFO;
  qbuf.fd = fd;
  qbuf.fid = fid;

  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  *mapi_lock = 0;

  if (qbuf.cmd == GET_FUNCTION_INFO_ACK)
  {
    memcpy(info, qbuf.data, sizeof(mapi_function_info_t));
    return 0;
  }
  else
  {
    *local_err = MAPI_FUNCTION_INFO_ERR;
    return -1;
  }
}

int flowdrv_get_flow_info(flowlist_t *flow_item, mapi_flow_info_t *info)
{
  struct mapiipcbuf qbuf;
  flowdescr_t* flow;
  
  flow = (flowdescr_t *) flow_item->flowdescr;

  qbuf.mtype = 1;
  qbuf.cmd = GET_FLOW_INFO;
  qbuf.fd = flow->fd;

  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  *mapi_lock = 0;

  if (qbuf.cmd == GET_FLOW_INFO_ACK)
  {
    memcpy(info, qbuf.data, sizeof(mapi_flow_info_t));
    return 0;
  }
  else
  {
    *local_err = MAPI_FLOW_INFO_ERR;
    return -1;
  }
}

int flowdrv_get_next_flow_info(int fd, mapi_flow_info_t *info)
{
  struct mapiipcbuf qbuf;

  pthread_once(&mapi_is_initialized, (void*)mapi_init);

  qbuf.mtype = 1;
  qbuf.cmd = GET_NEXT_FLOW_INFO;
  qbuf.fd = fd;

  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  *mapi_lock = 0;

  if (qbuf.cmd == GET_FLOW_INFO_ACK)
  {
    memcpy(info, qbuf.data, sizeof(mapi_flow_info_t));
    return 0;
  } 
  else
  {
    *local_err = MAPI_FLOW_INFO_ERR;
    return -1;
  }
}

int flowdrv_get_next_device_info(int devid, mapi_device_info_t *info)
{
  struct mapiipcbuf qbuf;

  pthread_once(&mapi_is_initialized, (void*)mapi_init);

  qbuf.mtype = 1;
  qbuf.cmd = GET_NEXT_DEVICE_INFO;
  qbuf.fd = devid;

  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  *mapi_lock = 0;

  if (qbuf.cmd == GET_DEVICE_INFO_ACK)
  {
    memcpy(info, qbuf.data, sizeof(mapi_device_info_t));
    return 0;
  } 
  else
  {
    *local_err = MAPI_DEVICE_INFO_ERR;
    return -1;
  }
}

int flowdrv_get_device_info(int devid, mapi_device_info_t *info)
{
  struct mapiipcbuf qbuf;
//  flowdescr_t *flow;
  
//    flow = (flowdescr_t *) flow_item->flowdescr;

  pthread_once(&mapi_is_initialized, (void*)mapi_init);

  qbuf.mtype = 1;
  qbuf.cmd = GET_DEVICE_INFO;
  qbuf.fd = devid;

  while(__sync_lock_test_and_set(mapi_lock,1));
  if (mapiipc_write((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    *mapi_lock = 0;
    return -1;
  }
  *mapi_lock = 0;

  if (qbuf.cmd == GET_DEVICE_INFO_ACK)
  {
    memcpy(info, qbuf.data, sizeof(mapi_device_info_t));
    return 0;
  }
  else
  {
    *local_err = MAPI_DEVICE_INFO_ERR;
    return -1;
  }
}

int flowdrv_stats(const char *dev, struct mapi_stat *stats)
{
  struct mapiipcbuf qbuf;
  
  strncpy((char *)qbuf.data, dev, DATA_SIZE);

  qbuf.mtype = 1;
  qbuf.cmd = MAPI_STATS;
  qbuf.fd = getpid();
  qbuf.pid = getpid();
  
  pthread_once(&mapi_is_initialized, (void*)mapi_init);
  
  // Stats is not really a flow, but we pretend it is so we can use same socket open/close code
  while(__sync_lock_test_and_set(mapi_lock,1));

  if (((*get_numflows)() == 0) && ((*get_totalflows)() > 0) && *minit){ // socket has been closed, re-create it
    if (mapiipc_client_init() == -1) {
      *local_err = MCOM_INIT_SOCKET_ERROR;
      *mapi_lock = 0;
      return -1;
    }
    (*incr_numflows)();
  }
  else 
    (*incr_numflows)();

  if (mapiipc_write((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    (*decr_numflows)();
    *mapi_lock = 0;
    return -1;
  }
  if (mapiipc_read((struct mapiipcbuf*) &qbuf) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    (*decr_numflows)();
    *mapi_lock = 0;
    return -1;
  }
  
  (*incr_totalflows)();
  
  // release socket resources if there is no other flows using it
  if (((*decr_numflows)() == 0) && offline_devices == 0)
    mapiipc_client_close();

  *mapi_lock = 0;
  
  switch(qbuf.cmd)
  {
    case MAPI_STATS_ACK:
      memcpy(stats, qbuf.data, sizeof(struct mapi_stat));
      strncpy(stats->hostname, "localhost", MAPI_STR_LENGTH);
      strncpy(stats->dev, dev, MAPI_STR_LENGTH);
      return 1;
      
    case MAPI_STATS_ERR:
      *local_err = qbuf.remote_errorcode;    
      return -1;
      
    default:
      *local_err = MAPI_STATS_ERROR;
      return -1;
  }
}

char * flowdrv_get_devtype_of_flow(flowlist_t *flow_item)
{
  flowdescr_t *flow;
  char *devtype = NULL;
  
  flow = (flowdescr_t *) flow_item->flowdescr;
  if (flow->devtype != NULL)
    devtype = strdup(flow->devtype);

  return devtype;
}

/* ** IPC calls ** */

int mapiipc_client_init()
//Initializes IPC for mapi functions
{
  if ((sock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
  {
    printf("ERROR: socket (%s) [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
    return -1;
  }

  // Check that names of mapid's sockets were set
  if(mapidsocket == NULL || mapidsocketglobal == NULL)
  {
    printf("ERROR: mapiipc_client_init() - socket names not set [%s:%d]\n", __FILE__, __LINE__);
    return -1;
  }

  // construct socket (try local)
  mapidaddr.sun_family = AF_LOCAL;
  strcpy(mapidaddr.sun_path, mapidsocket);
  mapidaddr_len = sizeof(mapidaddr.sun_family) + strlen(mapidaddr.sun_path);

  if (connect(sock, (struct sockaddr *)&mapidaddr, mapidaddr_len) < 0) 
  {
    // construct socket (try global)
    strcpy(mapidaddr.sun_path, mapidsocketglobal);
    mapidaddr_len = sizeof(mapidaddr.sun_family) + strlen(mapidaddr.sun_path);
    if (connect(sock, (struct sockaddr *)&mapidaddr, mapidaddr_len) < 0)
    {
      printf("ERROR: connect (%s) [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
      return -1;
    }
  }
  return 0;
}

// Sets globals (each thread)
int mapiipc_set_socket_names(char *socket, char *socketglobal)
{
  if (mapidsocket != NULL) free(mapidsocket);
  if (mapidsocketglobal != NULL) free(mapidsocketglobal);
  mapidsocket = strdup(socket);
  mapidsocketglobal = strdup(socketglobal);

  return 0;
}

int mapiipc_write(struct mapiipcbuf *qbuf)
// sends an IPC message to mapid
{
  qbuf->uid = getuid();   // returns the real user ID of the current process
  
  if (send(sock, qbuf, sizeof(struct mapiipcbuf), MSG_NOSIGNAL) == -1)
  {
    WARNING_CMD(printf("\nsend: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__));
    return -1;
  }
  return 0;
}

int mapiipc_read(struct mapiipcbuf *qbuf)
//Reads an IPC message. Blocking call
{
  if (recv(sock, qbuf, MAX_SEND_SIZE, 0) == -1)
  {
    printf("ERROR: recv (%s) [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
    return -1;
  }
  return 0;
}

int mapiipc_send_fd(int sendfd)
{
  struct msghdr msg;
  struct iovec iov[1];
  char ptr[2];
  int ret;

#ifdef HAVE_MSGHDR_MSG_CONTROL
  union {
    struct cmsghdr cm;
    char control[CMSG_SPACE(sizeof(int))];
  } control_un;
  struct cmsghdr  *cmptr;

  msg.msg_control = control_un.control;
  msg.msg_controllen = sizeof(control_un.control);

  cmptr = CMSG_FIRSTHDR(&msg);
  cmptr->cmsg_len = CMSG_LEN(sizeof(int));
  cmptr->cmsg_level = SOL_SOCKET;
  cmptr->cmsg_type = SCM_RIGHTS;
  *((int *) CMSG_DATA(cmptr)) = sendfd;
#else
  msg.msg_accrights = (caddr_t) &sendfd;
  msg.msg_accrightslen = sizeof(int);
#endif

  iov[0].iov_base = ptr;
  iov[0].iov_len = 2;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;

  ret = sendmsg(sock, &msg, 0);
  return(ret);
}


int mapiipc_read_fd(int sock)
{
  struct msghdr msg;
  struct iovec iov[1];
  ssize_t n;
  int recvfd;
  char c[2];

#ifdef HAVE_MSGHDR_MSG_CONTROL
  union {
    struct cmsghdr cm;
    char control[CMSG_SPACE(sizeof(int))];
  } control_un;
  struct cmsghdr *cmptr;

  msg.msg_control = control_un.control;
  msg.msg_controllen = sizeof(control_un.control);
#else
  msg.msg_accrights = (caddr_t) &newfd;
  msg.msg_accrightslen = sizeof(int);
#endif

  iov[0].iov_base = &c;
  iov[0].iov_len = 2;
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_name = NULL;
  msg.msg_namelen = 0;

  if ((n = recvmsg(sock, &msg, 0)) <= 0)
    return(n);

#ifdef HAVE_MSGHDR_MSG_CONTROL
  if ((cmptr = CMSG_FIRSTHDR(&msg)) != NULL &&
      cmptr->cmsg_len == CMSG_LEN(sizeof(int)))
  {
    if (cmptr->cmsg_level != SOL_SOCKET)
    {
      printf("ERROR: control level != SOL_SOCKET [%s:%d]\n", __FILE__, __LINE__);
      return -1;
    }
    if (cmptr->cmsg_type != SCM_RIGHTS)
    {
      printf("ERROR: control type != SCM_RIGHTS [%s:%d]\n", __FILE__, __LINE__);
      return -1;
    }
    recvfd = *((int *) CMSG_DATA(cmptr));
  }
  else
    recvfd = -1;    /* descriptor was not passed */
#else
  if (msg.msg_accrightslen == sizeof(int))
    recvfd = newfd;
  else
    recvfd = -1;    /* descriptor was not passed */
#endif

  return recvfd;
}

void mapiipc_client_close()
//Releases socket resources
{
  close(sock);
}
