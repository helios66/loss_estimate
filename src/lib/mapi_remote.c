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
#include "parseconf.h"
#include "mapi_errors.h"
#include "mapi_flowdrv.h"
#include "mapi_remote.h"

#include <signal.h>
#include <semaphore.h>

#include <netdb.h>
#include <netinet/in.h>
#include <semaphore.h>
#include "flist.h"

#define HAVE_MSGHDR_MSG_CONTROL 1 // Why do we have this ?

// TODO: clean up unneeded header files.

static pthread_once_t dmapi_is_initialized = PTHREAD_ONCE_INIT;
static int *minit; //Set to 1 when MAPI has been initialized
static boolean_t globals_set = 0;

static int *mapi_lock;

static int *local_err; /* occurence of a mapi.c error, translation of these errors */

static int *agent;

static flist_t **flowlist; // defined in mapi.c
static int *fd_counter; // pre incr and use.
static void **remotedrv; // XXX: make a more dynamic system?

flist_t *hostlist = NULL;//list containing all remote hosts used so far
int dimapi_port;
static sem_t stats_sem;

typedef struct function_data {
  int fid;      // real fid returned from mapicommd
  int fidseed;  // fid returned to mapi user
  mapidflib_function_def_t *fdef; // function definition
  struct dmapiipcbuf *dbuf;       // need for asynchronous mapi_read_results
} function_data;

static int hostlist_lock;

static unsigned fidseed = 0;       // function descriptor seed (always increases)
static unsigned negfdseed = -1;      // generates temporary negative fd, for use before create_flow

/*
 * Function declarations 
 */
static int hostcmp(void *h1, void *h2);
static void delete_remote_flow(flowlist_t *flow_item);

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
  
  remotedrv = globals->remotedrv;
  
  get_numflows = globals->get_numflows;
  incr_numflows = globals->incr_numflows;
  decr_numflows = globals->decr_numflows;
  get_totalflows = globals->get_totalflows;
  incr_totalflows = globals->incr_totalflows;
  
  globals_set = 1;
}

//Initializes MAPI - called only once by pthread_once()
void dmapi_init()
{
  if (!globals_set)
  {
    fprintf(stderr, "\nERROR: driver not initialized!\n");
    return;
  }
  
  char *libpath = NULL, *libs = NULL, *str = NULL, *s = NULL;
  char *mapi_conf;
  conf_category_t *conf;
  
  mapi_conf = printf_string(CONFDIR"/"CONF_FILE);

  if ((conf = pc_load (mapi_conf)) != NULL)
  {
      conf_category_entry_t *empty_cat = pc_get_category(conf, "");
      const char *portstr;

      if (empty_cat == NULL)
      {
          printf("Configuration file has no empty category. Giving up\n");
          exit(1);
      }
      libpath = pc_get_param (empty_cat, "libpath");
      libs = pc_get_param (empty_cat, "libs");
      portstr = pc_get_param (empty_cat, "dimapi_port");
      if (portstr == NULL)
      {
        printf("ERROR: Configuration file has no entry for `dimapi_port'. Using default port %d\n", DEFAULT_DIMAPI_PORT);
        dimapi_port = DEFAULT_DIMAPI_PORT;
      }
      else {
        /* make sure that portstr is a valid number. */
        dimapi_port = atoi(portstr);
        if (dimapi_port <= 0 || dimapi_port >= 65536)
        {
          printf("ERROR: Invalid port given in configuration file. The default port %d is used\n", DEFAULT_DIMAPI_PORT);
          dimapi_port = DEFAULT_DIMAPI_PORT;
        }
      }
  }
  else 
  {
    printf("ERROR: Cannot load mapi.conf file. Giving up.\n");
    printf("Search path is: %s\n", mapi_conf);
    exit(1);
  }

  *minit = 1;

  hostlist = malloc(sizeof(flist_t));
  flist_init(hostlist); 

  //Load function libraries
  str = libs;
  while((s = strchr(str, ':')) != NULL)
  {
    *s = '\0';
    mapilh_load_library(libpath, str);
    str = s + 1;
  }

  mapilh_load_library(libpath, str);
  free(mapi_conf);
  pc_close(conf);
  return;
}

int flowdrv_connect(flowlist_t *flow_item)
//Connect to a mapi flow
//flow_item = the flowlist entry for the remote flow
{
  remote_flowdescr_t *rflow;
  host_flow* hflow;
  flist_node_t* fnode;
  
  rflow = (remote_flowdescr_t *) flow_item->flowdescr;

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    hflow->dbuf->cmd = CONNECT;
    hflow->dbuf->fd = hflow->fd;
    hflow->dbuf->length = BASIC_SIZE;
  }

  if (mapiipc_remote_write_to_all(rflow) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }

  //wait results

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;

    switch (hflow->dbuf->cmd)
    {
      case CONNECT_ACK:
        rflow->is_connected = 1;
        continue;
      case ERROR_ACK:
        memcpy(local_err, hflow->dbuf->data, sizeof(int));
        return -1;
      default:
        *local_err = MCOM_UNKNOWN_ERROR;
        return -1;
    }
  }
  return 0;
}

static void delete_remote_flow(flowlist_t *flow_item)
{
  remote_flowdescr_t *rflow = (remote_flowdescr_t *) flow_item->flowdescr;
  host_flow *hflow;
  flist_node_t *fnode, *fnode2, *fnode3;
  mapi_results_t *res;
  function_data *fdata;
  //int count; //FIXME: async gnp

  while(__sync_lock_test_and_set(mapi_lock,1));
  flist_remove(*flowlist, flow_item->fd);
  (*decr_numflows)();
  *mapi_lock = 0;

  sem_destroy(&rflow->fd_sem);
  sem_destroy(&rflow->pkt_sem);

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = fnode2 )
  {
    fnode2 = flist_next(fnode);
    hflow = (host_flow*) fnode->data;
    hflow->rhost->num_flows--;
    flist_remove(hflow->rhost->flows, hflow->fd);

    for (fnode3 = flist_head(hflow->functions); fnode3 != NULL; fnode3 = flist_next(fnode3))
    {
      fdata = (function_data *) flist_remove(hflow->rhost->functions, ((function_data*)fnode3->data)->fidseed);
      if (fdata->dbuf != NULL)
      {
        free(fdata->dbuf);
        fdata->dbuf = NULL;
      }
      free(fdata);
    }

    if (hflow->rhost->num_flows == 0)
    {
      while(__sync_lock_test_and_set(&hostlist_lock,1));
      
      pthread_cancel(*hflow->rhost->comm_thread);
      mapiipc_remote_close(hflow->rhost);	//close the socket
      flist_destroy(hflow->rhost->flows);
      free(hflow->rhost->flows);
      flist_destroy(hflow->rhost->functions);
      free(hflow->rhost->functions);
      free(hflow->rhost->hostname);
      flist_remove(hostlist, hflow->rhost->sockfd);
      free(hflow->rhost->comm_thread);
      free(hflow->rhost);
      
      hostlist_lock = 0;
    }
    
    //we check if a host is using in other rflows and delete it -close the socket- if not
    flist_destroy(hflow->functions);
    free(hflow->functions);
    free(hflow->dev);
    free(hflow->devtype);
    free(hflow->dbuf);
    if (hflow->pkt != NULL)
      free(hflow->pkt);

    /* FIXME: do we want async get next pkt?
    if (hflow->asyn_pkts != NULL)
    {
      // release resources of mapi_asynchronous_get_next_pkt()
      for(count = 0; count < ASYN_GNP_BUFFER_SIZE; count++)
        free(hflow->asyn_pkts->pkts[count]);

      free(hflow->asyn_pkts->pkts);
      free(hflow->asyn_pkts);

      pthread_cancel(*hflow->asyn_comm_thread);
      mapiipc_remote_close_asyn(hflow);
      free(hflow->asyn_comm_thread);
      // TODO close the new socket
    }*/

    flist_remove(rflow->host_flowlist, hflow->id);
    free(hflow);
  }
  flist_destroy(rflow->host_flowlist);
  free(rflow->host_flowlist);
  if (rflow->pkt_list != NULL)
  {
    flist_destroy(rflow->pkt_list);
    free(rflow->pkt_list);
  }
  for (fnode = flist_head(rflow->function_res); fnode != NULL; fnode = fnode2 )
  { 
    fnode2 = flist_next(fnode);
    res = (mapi_results_t*) fnode->data;
    free(res->res);
    free(res);
  }
  flist_destroy(rflow->function_res);
  free(rflow->function_res);
  if (rflow->pkt != NULL)
    free(rflow->pkt);
  free(rflow);
  free(flow_item);
}

int flowdrv_create_flow(const char *dev)
//Create new flow
//dev = device that should be used
{
  remote_flowdescr_t *rflow;
  char *hostname=NULL, *s=NULL, *k=NULL;
  struct host *h=NULL;
  host_flow* hflow = NULL;
  char *devp;
  flist_node_t* fnode;
  unsigned int idgen=0;

  pthread_once(&dmapi_is_initialized, (void*)dmapi_init);
  
  devp = strdup(dev);
  rflow = (remote_flowdescr_t *) malloc(sizeof(remote_flowdescr_t));
  rflow->fd = ++(*fd_counter);
  sem_init(&rflow->fd_sem, 0, 0);
  sem_init(&rflow->pkt_sem, 0, 0);
  rflow->host_flowlist = (flist_t*) malloc(sizeof(flist_t));
  flist_init(rflow->host_flowlist);
  rflow->pkt_list = NULL;
  rflow->function_res = (flist_t*) malloc(sizeof(flist_t));
  rflow->is_connected = 0;
  //rflow->is_asyn_gnp_called = 0; //FIXME: async gnp
  rflow->pkt = NULL;
  flist_init(rflow->function_res);
  k = strtok(devp, ", ");

  while (k != NULL)
  {
    if ((s = strchr(k, ':')) != NULL)
    {
      *s = '\0';
      hostname = k;
      k = s + 1;
      
      while(__sync_lock_test_and_set(&hostlist_lock,1));
      
      h = (struct host *) flist_search(hostlist, hostcmp, hostname);

      if (h == NULL)
      {
        // Our host is a new one --> insert it in the hostlist
        h = (struct host *) malloc(sizeof(struct host));
        h->hostname = strdup(hostname);
        h->port = dimapi_port;
        h->flows = (flist_t *) malloc(sizeof(flist_t));
        flist_init(h->flows);
        h->functions = (flist_t *) malloc(sizeof(flist_t));
        flist_init(h->functions);
        h->num_flows = 0;
        h->stats = NULL;

        // Create the socket
        if (mapiipc_remote_init(h) < 0)
        {
          *local_err = MCOM_SOCKET_ERROR;
          printf("ERROR: Could not connect with host %s [%s:%d]\n", h->hostname, __FILE__, __LINE__);
          flist_destroy(h->flows);
          free(h->flows);
          flist_destroy(h->functions);
          free(h->functions);
          free(h->hostname);
          free(h);
          hostlist_lock = 0;
          return -1;
        }

        h->comm_thread = (pthread_t *) malloc(sizeof(pthread_t));
        pthread_create(h->comm_thread, NULL, *mapiipc_comm_thread, h);

        flist_append(hostlist, h->sockfd, h);
        hostlist_lock = 0;
      }
      else
      {
        //host exists in the list
        hostlist_lock = 0;
      }

      h->num_flows++;
      hflow = (host_flow*) malloc(sizeof(host_flow));
      hflow->scope_fd = rflow->fd;
      hflow->dev = strdup(k);
      hflow->devtype = NULL;
      flist_append(rflow->host_flowlist, ++idgen, hflow);
      hflow->id = idgen;
      flist_append(h->flows, --negfdseed, hflow);
      hflow->fd = negfdseed;
      hflow->dbuf = (struct dmapiipcbuf *) malloc(sizeof(struct dmapiipcbuf));
      hflow->pkt = NULL;
      //hflow->asyn_pkts = NULL; // FIXME: async gnp
      hflow->rhost = h;
      hflow->functions = (flist_t *) malloc(sizeof(flist_t));
      //pthread_spin_init(&(hflow->asyn_get_next_pkt_lock), PTHREAD_PROCESS_PRIVATE); // FIXME: async gnp
      flist_init(hflow->functions);

      hflow->dbuf->cmd = CREATE_FLOW;
      strncpy((char *) hflow->dbuf->data, k, DATA_SIZE);
      hflow->dbuf->length = BASIC_SIZE + strlen(k) + 1;
    }
    else
    {
      //this is the case where the dev string contains both 'host:interface1' and 'interface2'
      //example: mapi_create_flow("139.91.70.98:eth0, 147.52.16.102:eth0, eth1");
      //user's intention is probably localhost:eth1
      //what should be done in this case?
    }
    k = strtok(NULL, ", ");
  }

  free(devp);

  rflow->scope_size = flist_size(rflow->host_flowlist);

  
  flowlist_t *flow_item = malloc(sizeof(flowlist_t));
  if (flow_item == NULL)
  {
    printf("ERROR: Out of memory [%s:%d]\n", __FILE__, __LINE__);
    return -1;
  }

  while(__sync_lock_test_and_set(mapi_lock,1));
  
  flow_item->fd = *fd_counter;
  flow_item->flowtype = FLOWTYPE_REMOTE;
  flow_item->driver = *remotedrv; // get_driver ?
  flow_item->flowdescr = rflow;
  
  flist_append(*flowlist, *fd_counter, flow_item);
  (*incr_numflows)();
  (*incr_totalflows)();
  
  *mapi_lock = 0;

  if (mapiipc_remote_write_to_all(rflow) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }
  //sends to all hosts of rflow the proper dbuf, increment the pending_msgs makes sem_wait(rflow->fd_sem) and the comm_thread will get the results - the hflow->fd for every flow -

  //wait for results

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow*) fnode->data;
    if (hflow->dbuf->cmd == CREATE_FLOW_ACK)
    {
      hflow->fd = *((int*) hflow->dbuf->data);
      if (hflow->dbuf->length - BASIC_SIZE > sizeof(int))
        hflow->devtype = strndup((char *)(((char *)hflow->dbuf->data) + sizeof(int)), hflow->dbuf->length - BASIC_SIZE - sizeof(int) - 1);
      else
        hflow->devtype = strndup("1.3", 3);
        
      flist_remove(hflow->rhost->flows, hflow->dbuf->fd);
      flist_append(hflow->rhost->flows, hflow->fd, hflow);
    }
    else if (hflow->dbuf->cmd == ERROR_ACK)
    {
      memcpy(local_err, hflow->dbuf->data, sizeof(int));
      printf("ERROR: Could not create flow in host %s [%s:%d]\n", hflow->rhost->hostname, __FILE__, __LINE__);
      delete_remote_flow(flow_item);
      return -1;
    }
    else
    {
      *local_err = MCOM_UNKNOWN_ERROR;
      delete_remote_flow(flow_item);
      return -1;
    }
  }

  return *fd_counter;
}

char *flowdrv_create_offline_device(MAPI_UNUSED const char *path, MAPI_UNUSED int format)
// Create new offline device
// path = tracefile that should be used
// format = tracefile format constant
{
  printf("ERROR: Remote driver does not support offline devices.\n");
  return NULL;
}

int flowdrv_start_offline_device(MAPI_UNUSED const char *dev)
//Start offline device
//dev = offline device that should be used
{
  printf("ERROR: Remote driver does not support offline devices.\n");
  return -1;
}

int flowdrv_delete_offline_device(MAPI_UNUSED char *dev)
// Delete offline device
// dev = offline device that should be deleted
{
  printf("ERROR: Remote driver does not support offline devices.\n");
  return -1;
}

int flowdrv_close_flow(flowlist_t *flow_item) 
{
  remote_flowdescr_t *rflow = (remote_flowdescr_t *) flow_item->flowdescr;
  host_flow *hflow;  
  flist_node_t *fnode;

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    hflow->dbuf->cmd = CLOSE_FLOW;
    hflow->dbuf->fd = hflow->fd;
    hflow->dbuf->length = BASIC_SIZE;
  }

  rflow->is_connected = 0;

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    hflow->dbuf->fd = hflow->fd;
    if (mapiipc_remote_write(hflow->dbuf, hflow->rhost) < 0)
    {
      *local_err = MCOM_SOCKET_ERROR;
      return -1;
    }
  }

  delete_remote_flow(flow_item);
  return 0;
}

int flowdrv_apply_function(flowlist_t *flow_item, const char *funct, va_list vl) 
//Apply function to a mapi flow
//flow_item: flowlist entry with flow descriptor
//funct: function to be added
{
  int tmp, i;
  unsigned long long ltmp;
  char ctmp, *argdescr_ptr, *filename, *temp;
  char *fids;
  unsigned char* args;    //in case read from a buffer instead of va_list
  mapidflib_function_def_t *fdef;
  mapiFunctArg *pos;
  unsigned char buffer[DATA_SIZE];
  unsigned int arg_size=0;
  

  remote_flowdescr_t *rflow, *ref_flow;
  flowlist_t *ftmp;
  host_flow *hflow;
  function_data *fdata;
  flist_node_t *fnode;
  char buf[DATA_SIZE], *cfids, *s, *new_fids;
  int fid_, fd_, tmp_fd, tmp_fid, len = 0;
  rflow = (remote_flowdescr_t *) flow_item->flowdescr;

  if (rflow->is_connected)
  {
    printf("ERROR: Can not apply function %s on an already connected flow\n", funct);
    *local_err = MFUNCT_COULD_NOT_APPLY_FUNCT;
    return -1;
  }
  
  for (fnode = flist_head(rflow->host_flowlist), i = 1; fnode != NULL; fnode = flist_next(fnode), i++)
  {
    hflow = (host_flow *) fnode->data;

    fdef = mapilh_get_function_def(funct, hflow->devtype);
    if (fdef == NULL)
    {
      printf("ERROR: Could not find/match function %s [%s:%d]\n", funct, __FILE__, __LINE__);
      *local_err = MAPI_FUNCTION_NOT_FOUND;
      return -1;
    }

    hflow->dbuf->cmd = APPLY_FUNCTION;
    hflow->dbuf->fd = hflow->fd;
    memcpy(hflow->dbuf->data, funct, strlen(funct) + 1);  //put function name in the buffer

    pos = buffer;  // point to start of arguments buffer
    arg_size = 0;

    if (*agent == 1)
    {
      args = va_arg(vl, unsigned char*);
    }

    // parse function arguments
    if (strncmp(fdef->argdescr, "", 1))
    {
      // there are some args
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
              temp = (char*) args;
              args += strlen(temp) + 1;
            }
            addarg(&pos, temp, STRING);
            arg_size += strlen(temp) + 1;
            break;
            
          case 'S':   // reference to flows and functions (e.g RES2FILE)
            if (*agent == 0)
              fids = va_arg(vl, char *);
            else
            {
              fids = (char *)args;
              args += strlen(fids) + 1;
            }
            
            // allocate more bytes, because we can have the following case: 7@2,8@2,9@2 translated to 12@3,13@3,14@3
            new_fids = (char *)malloc(strlen(fids) * 10 * sizeof(char));
            strncpy(buf, fids, DATA_SIZE);
            cfids = buf;
            
            while ((s = strchr(cfids, ',')) != NULL)
            {
              *s = '\0';
              sscanf(cfids, "%d@%d", &fid_, &fd_);
              ftmp = flist_get(*flowlist, fd_);
              if (ftmp != NULL && ftmp->flowtype == FLOWTYPE_REMOTE)
                ref_flow = (remote_flowdescr_t *) ftmp->flowdescr;
              else
                ref_flow = NULL;
              
              if (ref_flow == NULL || i > ref_flow->scope_size)
              {
                printf("ERROR: Invalid flow in function arguments [%s:%d]\n", __FILE__, __LINE__);
                *local_err = MAPI_INVALID_FID_FUNCID;
                return -1;
              }
              tmp_fd = ((host_flow *) flist_get(ref_flow->host_flowlist, i))->fd;
              
              fdata = flist_get(hflow->rhost->functions, fid_);
              
              if (fdata == NULL)
              {
                printf("ERROR: Invalid fid in function arguments [%s:%d]\n", __FILE__, __LINE__);
                *local_err = MAPI_INVALID_FID_FUNCID;
                return -1;
              }
              tmp_fid = fdata->fid;
              
              if (len != 0)
                len += sprintf(new_fids + len, ",");
                
              len += sprintf(new_fids + len, "%d", tmp_fid);
              len += sprintf(new_fids + len, "@");
              len += sprintf(new_fids + len, "%d", tmp_fd);
              
              cfids = s + 1;
            }
            
            sscanf(cfids, "%d@%d", &fid_, &fd_);
            ftmp = flist_get(*flowlist, fd_);
            if (ftmp != NULL && ftmp->flowtype == FLOWTYPE_REMOTE)
              ref_flow = (remote_flowdescr_t *) ftmp->flowdescr;
            else
              ref_flow = NULL;
            
            if (ref_flow == NULL || i > ref_flow->scope_size)
            {
              printf("ERROR: Invalid flow in function arguments [%s:%d]\n", __FILE__, __LINE__);
              *local_err = MAPI_INVALID_FID_FUNCID;
              return -1;
            }
            tmp_fd = ((host_flow *) flist_get(ref_flow->host_flowlist, i))->fd;
            
            fdata = flist_get(hflow->rhost->functions, fid_);
            
            if (fdata == NULL)
            {
              printf("ERROR: Invalid fid in function arguments [%s:%d]\n", __FILE__, __LINE__);
              *local_err = MAPI_INVALID_FID_FUNCID;
              return -1;
            }
            tmp_fid = fdata->fid;
            
            if(len != 0)
              len += sprintf(new_fids + len, ",");
              
            len += sprintf(new_fids + len, "%d", tmp_fid);
            len += sprintf(new_fids + len, "@");
            len += sprintf(new_fids + len, "%d", tmp_fd);
            
            addarg(&pos, new_fids, STRING);
            arg_size += strlen(new_fids) + 1;
            len = 0;
            free(new_fids);
            new_fids = NULL;
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
            arg_size += sizeof(int);
            break;
            
          case 'r':   //reference to a flow
            if (*agent == 0)
              tmp = va_arg(vl, int);
            else
            {
              memcpy(&tmp, args, sizeof(int));
              args += sizeof(int);
            }
            
            ftmp = flist_get(*flowlist, tmp);
            if (ftmp != NULL && ftmp->flowtype == FLOWTYPE_REMOTE)
              ref_flow = (remote_flowdescr_t *) ftmp->flowdescr;
            else
              ref_flow = NULL;

            if (ref_flow == NULL || i > ref_flow->scope_size)
            {
              printf("ERROR: Invalid flow in function arguments [%s:%d]\n", __FILE__, __LINE__);
              *local_err = MAPI_INVALID_FID_FUNCID;
              return -1;
            }
            tmp = ((host_flow *) flist_get(ref_flow->host_flowlist, i))->fd;
            addarg(&pos, &tmp ,INT);
            arg_size += sizeof(int);
            break;
            
          case 'f':   //reference to a fuction
            if (*agent == 0)
              tmp = va_arg(vl, int);
            else
            {
              memcpy(&tmp, args, sizeof(int));
              args += sizeof(int);
            }

            fdata = flist_get(hflow->rhost->functions, tmp);

            if (fdata == NULL)
            {
              printf("ERROR: Invalid fid in function arguments [%s:%d]\n", __FILE__, __LINE__);
              *local_err = MAPI_INVALID_FID_FUNCID;
              return -1;
            }
            tmp = fdata->fid;
            addarg(&pos, &tmp,INT);
            arg_size += sizeof(int);
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
            arg_size += sizeof(char);
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
            arg_size += sizeof(unsigned long long);
            break;
            
          case 'w':   // open file for writing
            if (*agent == 0)
              filename = va_arg(vl, char*);
            else
            {
              filename = (char*) args;
              if (filename != NULL)
                args += strlen(filename) + 1;
            }
            if (filename == NULL)
            {
              *local_err = MAPI_ERROR_FILE;
              return -1;
            }
            addarg(&pos, filename, STRING);
            arg_size += strlen(filename) + 1;
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

    memcpy(hflow->dbuf->data + strlen(funct) + 1, buffer, arg_size); //argument size
    hflow->dbuf->length = BASIC_SIZE + strlen(funct) + 1 + arg_size;
  }

  if (mapiipc_remote_write_to_all(rflow) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }

  fidseed++;

  for (fnode = flist_head(rflow->host_flowlist), i = 1; fnode != NULL; fnode = flist_next(fnode), i++)
  {
    hflow = (host_flow *) fnode->data;
    
    switch (hflow->dbuf->cmd)
    {
      case APPLY_FUNCTION_ACK:
        fdata = (function_data *) malloc(sizeof(function_data));
        fdata->fid = hflow->dbuf->fid;
        fdata->fidseed = fidseed;
        fdata->fdef = fdef;
        fdata->dbuf = (struct dmapiipcbuf *) malloc(sizeof(struct dmapiipcbuf));  // for asynchronous mapi_read_results ...
        fdata->dbuf->length = 0;
        flist_append(hflow->functions, fidseed, fdata);
        flist_append(hflow->rhost->functions, fidseed, fdata);
        break;
        
      case ERROR_ACK:
        memcpy(local_err, hflow->dbuf->data, sizeof(int));
        return -1;
        
      default:
        *local_err = MCOM_UNKNOWN_ERROR;
        return -1;
    }
  }

  return fidseed;
}

// old signature: int mapi_read_results(int fd, int fid, void *result)
mapi_results_t *flowdrv_read_results(flowlist_t *flow_item, int fid)
//Read result from a function
//flow_item: flowlist entry with flow descriptor
//fid: ID of function
{
  remote_flowdescr_t *rflow = (remote_flowdescr_t *) flow_item->flowdescr;
  host_flow *hflow;
  unsigned int currhost = 0;
  flist_node_t *fnode;
  mapi_results_t *results;
  int i;
  function_data *fdata;

  if (!rflow->is_connected)
  {
    printf("ERROR: In mapi_read_results always use mapi_connect first\n");
    *local_err = MAPI_FLOW_NOT_CONNECTED;
    return NULL;
  }

  if ((results = flist_get(rflow->function_res, fid)) == NULL)
  {
    //init once
    results = (mapi_results_t *) malloc(sizeof(mapi_results_t) * rflow->scope_size);
    for (i = 0; i < rflow->scope_size; i++)
    {
      fdata = flist_get(((host_flow *) flist_head(rflow->host_flowlist)->data)->functions, fid);
      results[i].size = fdata->fdef->shm_size;
      results[i].res = (void *) malloc(results->size);
    }
    flist_append(rflow->function_res, fid, results);
  }

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    hflow->dbuf->cmd = READ_RESULT;
    hflow->dbuf->fd = hflow->fd;
    if ((fdata = (function_data *) flist_get(hflow->functions, fid)) == NULL)
    {
      *local_err = MAPI_INVALID_FID_FUNCID;
      return NULL;
    }

    hflow->dbuf->fid = fdata->fid;
    hflow->dbuf->length = BASIC_SIZE;
  }

  if (mapiipc_remote_write_to_all(rflow) < 0)
  { 
    *local_err = MCOM_SOCKET_ERROR;
    return NULL;
  }

  //wait results

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    switch (hflow->dbuf->cmd)
    {
      case READ_RESULT_ACK:
        if (hflow->dbuf->length - BASIC_SIZE > (unsigned int)results[currhost].size)  // check memory allocation
        {
          results[currhost].res = realloc(results[currhost].res, hflow->dbuf->length - BASIC_SIZE);
          results[currhost].size = hflow->dbuf->length - BASIC_SIZE;
        }
        memcpy(results[currhost].res, hflow->dbuf->data, hflow->dbuf->length - BASIC_SIZE);
        results[currhost].ts = hflow->dbuf->timestamp;
        results[currhost].size = hflow->dbuf->length - BASIC_SIZE;
        break;
      
      case ERROR_ACK:
        memcpy(local_err, hflow->dbuf->data, sizeof(int));
        return NULL;
        
      default:
        printf("ERROR: In read results! [%s:%d]\n", __FILE__, __LINE__);
        *local_err = MCOM_UNKNOWN_ERROR;
        return NULL;
    }
    ++currhost;
  }

  return(results);
}

/** \brief Get the next packet from a to_buffer function

	\param fd flow descriptor
	\param fid id of TO_BUFFER function

	\return Reference to next packet, or NULL on error
*/
struct mapipkt *
flowdrv_get_next_pkt(flowlist_t *flow_item, int fid) 
{
  remote_flowdescr_t *rflow;
  host_flow *hflow;
  flist_node_t *fnode;
  function_data *fdata;

  rflow = (remote_flowdescr_t *) flow_item->flowdescr;

  if (!rflow->is_connected)
  {
    printf("ERROR: In flowdrv_get_next_pkt always use flowdrv_connect first\n");
    *local_err = MAPI_FLOW_NOT_CONNECTED;
    return NULL;
  }
  
  //FIFO
  if (rflow->pkt_list == NULL)
  {
    rflow->pkt_list = (flist_t *) malloc(sizeof(flist_t));
    flist_init(rflow->pkt_list);
    rflow->pkt = (struct mapipkt *) malloc(sizeof(struct mapipkt) + PKT_LENGTH);

    for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
    {
      hflow = (host_flow *) fnode->data;
      hflow->pkt = (struct mapipkt *) malloc(sizeof(struct mapipkt) + PKT_LENGTH);
      hflow->dbuf->cmd = GET_NEXT_PKT;
      hflow->dbuf->fd = hflow->fd;
      if ((fdata = (function_data *) flist_get(hflow->functions, fid)) == NULL)
      {
        *local_err = MAPI_INVALID_FID_FUNCID;
        return NULL;
      }
      hflow->dbuf->fid = fdata->fid;
      hflow->dbuf->length = BASIC_SIZE;
      if (mapiipc_remote_write(hflow->dbuf, hflow->rhost) < 0)
      {
        *local_err = MCOM_SOCKET_ERROR;
        return NULL;
      }
    }

    sem_wait(&rflow->pkt_sem);  //wait at least one host packet
    hflow = (host_flow *) flist_pop_first(rflow->pkt_list);
    if (hflow == NULL)
    {
      *local_err= MCOM_UNKNOWN_ERROR;
      return NULL;
    }
    memcpy(rflow->pkt, hflow->pkt, sizeof(struct mapipkt) - 4 + hflow->pkt->caplen); // XXX: - 4 ?? bad ifdef in definition of struct?

    if ((fdata = (function_data *) flist_get(hflow->functions, fid)) == NULL)
      return NULL;
    
    //send request for next packet from this host
    hflow->dbuf->cmd = GET_NEXT_PKT;
    hflow->dbuf->fd = hflow->fd;
    hflow->dbuf->fid = fdata->fid;
    hflow->dbuf->length = BASIC_SIZE;
    if (mapiipc_remote_write(hflow->dbuf, hflow->rhost) < 0)
    {
      *local_err = MCOM_SOCKET_ERROR;
      return NULL;
    }
    
    if (rflow->pkt->caplen == 0)
    {
      return NULL;
    }
    
    return rflow->pkt;
  }
  else
  {
    //if no packet arrived yet wait
    sem_wait(&rflow->pkt_sem);
    hflow = (host_flow *) flist_pop_first(rflow->pkt_list);
    if (hflow == NULL)
    {
      return NULL;
    }

    memcpy(rflow->pkt, hflow->pkt, sizeof(struct mapipkt)-4+hflow->pkt->caplen);      

    if ((fdata = (function_data *) flist_get(hflow->functions, fid)) == NULL)
      return NULL;
    
    //send request for next packet from this host
    hflow->dbuf->cmd = GET_NEXT_PKT;
    hflow->dbuf->fd = hflow->fd;
    hflow->dbuf->fid = fdata->fid;
    hflow->dbuf->length = BASIC_SIZE;
    if (mapiipc_remote_write(hflow->dbuf, hflow->rhost) < 0)
    { 
      *local_err = MCOM_SOCKET_ERROR;
      return NULL;
    }
    
    /* No packet, return null */
    if (rflow->pkt->caplen == 0)
    {
      return NULL;
    }
    
    return rflow->pkt;
  }
}

int flowdrv_is_connected(flowlist_t *flow_item)
{
  remote_flowdescr_t *rflow;
  
  if (flow_item->flowdescr == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", flow_item->fd, __FILE__, __LINE__);
    *local_err = MAPI_INVALID_FLOW;
    return -1;
  }
  
  rflow = (remote_flowdescr_t *) flow_item->flowdescr;
  
  return rflow->is_connected;
}


// TODO: implement this?
// struct mapipkt* mapi_asynchronous_get_next_pkt(int fd, int fid){

int flowdrv_get_function_info(flowlist_t *flow_item, int fid, mapi_function_info_t *info)
{
  remote_flowdescr_t *rflow;
  host_flow *hflow;
  flist_node_t *fnode;
  function_data *fdata;
  
  rflow = (remote_flowdescr_t *) flow_item->flowdescr;

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    if ((fdata = (function_data *) flist_get(hflow->functions, fid)) == NULL )
    {
      *local_err = MAPI_FUNCTION_INFO_ERR;
      return -1;
    }
    hflow->dbuf->cmd = GET_FUNCTION_INFO;
    hflow->dbuf->fd = hflow->fd;
    hflow->dbuf->fid = fdata->fid;
    hflow->dbuf->length = BASIC_SIZE;
  }

  if (mapiipc_remote_write_to_all(rflow) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }

  //wait results

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    switch (hflow->dbuf->cmd)
    {
      case GET_FUNCTION_INFO_ACK:
        memcpy(info, hflow->dbuf->data, sizeof(mapi_function_info_t));
        continue;
      case ERROR_ACK:
        *local_err = MAPI_FUNCTION_INFO_ERR;
        return -1;
      default:
        *local_err = MAPI_FUNCTION_INFO_ERR;
        return -1;
    }
  }
  return 0;
}

int flowdrv_get_next_function_info(int fd, int fid, mapi_function_info_t *info)
{
  flowlist_t *flow_item;
  remote_flowdescr_t *rflow;
  host_flow *hflow;
  flist_node_t *fnode;
  function_data *fdata;

  if ((flow_item = flist_get(*flowlist, fd)) == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    *local_err = MAPI_INVALID_FLOW;
    return -1;
  }

  rflow = (remote_flowdescr_t *) flow_item->flowdescr;

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    hflow->dbuf->cmd = GET_NEXT_FUNCTION_INFO;
    hflow->dbuf->fd = hflow->fd;
    if ((fdata = (function_data *) flist_get(hflow->functions, fid)) == NULL)
    {
      *local_err = MAPI_FUNCTION_INFO_ERR;
      return -1;
    }
    hflow->dbuf->fid = fdata->fid;
    hflow->dbuf->length = BASIC_SIZE;
  }

  if (mapiipc_remote_write_to_all(rflow) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }

  //wait results

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    switch (hflow->dbuf->cmd)
    {
      case GET_FUNCTION_INFO_ACK:
        memcpy(info, hflow->dbuf->data, sizeof(mapi_function_info_t));
        continue;
      case ERROR_ACK:
        *local_err = MAPI_FUNCTION_INFO_ERR; 
        return -1;
      default:
        *local_err = MAPI_FUNCTION_INFO_ERR;
        return -1;
    }
  }
  return 0;
}

int flowdrv_get_flow_info(flowlist_t *flow_item, mapi_flow_info_t *info)
{
  remote_flowdescr_t *rflow = (remote_flowdescr_t *) flow_item->flowdescr;
  host_flow *hflow;
  flist_node_t *fnode;
  
  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
      hflow = (host_flow *) fnode->data;
      hflow->dbuf->cmd = GET_FLOW_INFO;
      hflow->dbuf->fd = hflow->fd;
      hflow->dbuf->length = BASIC_SIZE;
  }

  if (mapiipc_remote_write_to_all(rflow) < 0)
  { 
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }

  //wait results

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    switch (hflow->dbuf->cmd)
    {
      case GET_FLOW_INFO_ACK:
        memcpy(info, hflow->dbuf->data, sizeof(mapi_flow_info_t));
        info->devid = flow_item->fd;
        continue;
      case ERROR_ACK:
        *local_err = MAPI_FLOW_INFO_ERR; 
        return -1;
      default:
        *local_err = MAPI_FLOW_INFO_ERR;
        return -1;
    }
  }
  return 0;
}

int flowdrv_get_next_flow_info(int fd, mapi_flow_info_t *info)
{
  flowlist_t *flow_item;
  remote_flowdescr_t *rflow;
  host_flow *hflow;
  flist_node_t *fnode;

  if ((flow_item = flist_get(*flowlist, fd)) == NULL)
  {
    printf("ERROR: Invalid flow %d [%s:%d]\n", fd, __FILE__, __LINE__);
    *local_err = MAPI_INVALID_FLOW;
    return -1;
  }

  rflow = (remote_flowdescr_t *) flow_item->flowdescr;

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    hflow->dbuf->cmd = GET_NEXT_FLOW_INFO;
    hflow->dbuf->fd = hflow->fd;
    hflow->dbuf->length = BASIC_SIZE;
  }

  if (mapiipc_remote_write_to_all(rflow) < 0)
  { 
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }

  //wait results

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    switch (hflow->dbuf->cmd)
    {
      case GET_FLOW_INFO_ACK:
        memcpy(info, hflow->dbuf->data, sizeof(mapi_flow_info_t));
        info->devid = flow_item->fd;
        continue;
      case ERROR_ACK:
        *local_err = MAPI_FLOW_INFO_ERR; 
        return -1;
      default:
        *local_err = MAPI_FLOW_INFO_ERR;
        return -1;
    }
  }
  return 0;
}

int flowdrv_get_next_device_info(int devid, mapi_device_info_t *info)
{
  // Unsupported error
  // Would need an extra parameter for remote device, fd/flow_item or host
  *local_err = MAPI_DEVICE_INFO_ERR;
  printf("Error: get_next_device_info unsupported in dimapi\n");
  return -1;
  /* UNREACHED */

  remote_flowdescr_t *rflow = NULL;//(remote_flowdescr_t *) flow_item->flowdescr;
  host_flow *hflow;
  flist_node_t *fnode;
  int i = 0;

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow * ) fnode->data;
    hflow->dbuf->cmd = GET_NEXT_DEVICE_INFO;
    hflow->dbuf->fd = hflow->fd;
    hflow->dbuf->length = BASIC_SIZE;
  }

  if (mapiipc_remote_write_to_all(rflow) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }
  //wait results

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    switch (hflow->dbuf->cmd)
    {
      case GET_DEVICE_INFO_ACK:
        memcpy(&info[i++], hflow->dbuf->data, sizeof(mapi_device_info_t));
        continue;
      case GET_DEVICE_INFO_NACK:
        *local_err = MAPI_DEVICE_INFO_ERR;
        return -1;
      default:
        *local_err = MAPI_DEVICE_INFO_ERR;
        return -1;
    }
  }
  return 0;
}

int flowdrv_get_device_info(int devid, mapi_device_info_t *info)
{
  // Unsupported error
  // Would need an extra parameter for remote device, fd/flow_item or host
  *local_err = MAPI_DEVICE_INFO_ERR;
  printf("Error: get_device_info unsupported in dimapi\n");
  return -1;
  /* UNREACHED */

  remote_flowdescr_t *rflow = NULL;//(remote_flowdescr_t *) flow_item->flowdescr;
  host_flow *hflow;
  flist_node_t *fnode;
  int i = 0;

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    hflow->dbuf->cmd = GET_DEVICE_INFO;
    hflow->dbuf->fd = hflow->fd;
    hflow->dbuf->length = BASIC_SIZE;
  }

  if (mapiipc_remote_write_to_all(rflow) < 0)
  {
    *local_err = MCOM_SOCKET_ERROR;
    return -1;
  }
  //wait results

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    switch (hflow->dbuf->cmd)
    {
      case GET_DEVICE_INFO_ACK:
        memcpy(&info[i++], hflow->dbuf->data, sizeof(mapi_device_info_t));
        continue;
      case GET_DEVICE_INFO_NACK:
        *local_err = MAPI_DEVICE_INFO_ERR;
        return -1;
      default:
        *local_err = MAPI_DEVICE_INFO_ERR;
        return -1;
    }
  }
  return 0;
}

/* ** Special funcs ** */
static int hostcmp(void *h1, void *h2)
{
  struct host *h = (struct host *)h1;
  char *s = (char *)h2;
  return strcmp(h->hostname, s);
}

int flowdrv_get_scope_size(flowlist_t *flow_item)
{
  remote_flowdescr_t* rflow;

  if (flow_item != NULL)
  {
    if (flow_item->flowtype == FLOWTYPE_REMOTE)
    {
      rflow = (remote_flowdescr_t *) flow_item->flowdescr;
      return rflow->scope_size;
    }
    else
      return 0;
  }

  *local_err = MAPI_INVALID_FLOW;
  return -1;
}

// FIXME: is this used? seems pretty pointless
// if mapid and/or mapicommd are out of execution returns 1, otherwise returns 0
int mapi_is_sensor_down(MAPI_UNUSED int fd)
{
  return 0; // without reconnect always up ??
}

int flowdrv_stats(const char *dev, struct mapi_stat *stats)
{
  char *hostname = NULL, *s = NULL, *k = NULL;
  struct host *h = NULL;
  char *devp;
  struct dmapiipcbuf dbuf;
  int seed = 0;
  int i;

  pthread_once(&dmapi_is_initialized, (void*)dmapi_init);

  devp = strdup(dev);
  k = strtok(devp, ", ");

  sem_init(&stats_sem, 0, 0);

  while (k != NULL)
  {
    if ((s = strchr(k, ':')) != NULL)
    {
      *s = '\0';
      hostname = k;
      k = s + 1;
      while(__sync_lock_test_and_set(&hostlist_lock,1));
      h = (struct host *) flist_search(hostlist, hostcmp, hostname);

      if (h == NULL)
      {
        // Our host is a new one --> insert it in the hostlist
        h = (struct host *) malloc(sizeof(struct host));
        h->hostname = strdup(hostname);
        h->port = dimapi_port;
        h->flows = (flist_t *) malloc(sizeof(flist_t));
        flist_init(h->flows);
        h->functions = (flist_t *) malloc(sizeof(flist_t));
        flist_init(h->functions);
        h->num_flows = 0;
        h->stats = NULL;

        // Create the socket
        if (mapiipc_remote_init(h) < 0)
        {
          *local_err = MCOM_SOCKET_ERROR;
          printf("ERROR: Could not connect with host %s [%s:%d]\n", h->hostname, __FILE__, __LINE__);
          hostlist_lock = 0;
          return -1;
        }

        h->comm_thread = (pthread_t *) malloc(sizeof(pthread_t));
        pthread_create(h->comm_thread, NULL, *mapiipc_comm_thread, h);

        flist_append(hostlist, h->sockfd, h);
        hostlist_lock = 0;
      }
      else
      {
        //host exists in the list
        hostlist_lock = 0;
      }

      if (h->stats == NULL)
      {
        h->stats = (flist_t *) malloc(sizeof(flist_t));
        flist_init(h->stats);
      }

      strncpy(stats[seed].hostname, hostname, MAPI_STR_LENGTH);
      strncpy(stats[seed].dev, k, MAPI_STR_LENGTH);
      flist_append(h->stats, seed, &stats[seed]);

      dbuf.cmd = MAPI_STATS;
      strncpy((char *) dbuf.data, k, DATA_SIZE);
      dbuf.length = BASIC_SIZE + strlen(k) + 1;

      if (mapiipc_remote_write(&dbuf, h) < 0)
        return -1;

      seed++;
    }
    k = strtok(NULL, ", ");
  }

  free(devp);

  //wait for results
  for (i = 0; i < seed; i++)
    sem_wait(&stats_sem);

  sem_destroy(&stats_sem);
  return seed;
}

char * flowdrv_get_devtype_of_flow(MAPI_UNUSED flowlist_t *flow_item)
{
  // TODO/XXX: This could perhaps return an array with devtypes of the host_flows ? similiar to mapi_stats behaviour.
  return NULL;
}

/* ** IPC calls ** */

int mapiipc_remote_write(struct dmapiipcbuf *dbuf, struct host *h)
// sends an IPC message to mapid
{
#ifdef DIMAPISSL
  if(SSL_write(h->con, dbuf, dbuf->length) <= 0)
  {
    printf("WARNING: SSL_write (%s) [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
    return -1;
  }
#else
  if (send(h->sockfd, dbuf, dbuf->length, 0) == -1)
  {
    printf("WARNING: send (%s) [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
    return -1;
  }
#endif
  return 0;
}

int mapiipc_remote_write_to_all(remote_flowdescr_t *rflow)
{
  host_flow *hflow;
  flist_node_t *fnode;

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
    hflow = (host_flow *) fnode->data;
    hflow->dbuf->fd = hflow->fd;
    if (mapiipc_remote_write(hflow->dbuf, hflow->rhost) < 0)
      return -1;
  }

  for (fnode = flist_head(rflow->host_flowlist); fnode != NULL; fnode = flist_next(fnode))
  {
     sem_wait(&rflow->fd_sem);
  }

  return 0;
}

void cleanup_handler(void *arg)
//the cleanup handler
{
  free(arg);
  return;
}

void *mapiipc_comm_thread(void *host)
// reads an IPC message - blocking call
{
  struct dmapiipcbuf *dbuf;
  remote_flowdescr_t *rflow;
  flowlist_t *flow_item;
  host_flow *hflow;
  int recv_bytes;
  struct mapi_stat *stat;
  flist_node_t *fnode;

  // Guarantees that thread resources are deallocated upon return
  pthread_detach(pthread_self());
  pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);      // enable cancellation
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL); // changes the type of responses to cancellation requests for the calling thread
                                                            // asynchronous (cancel the calling thread as soon as the cancellation request is received)
  dbuf = (struct dmapiipcbuf *) malloc(sizeof(struct dmapiipcbuf));

  // pthread_cleanup_push() function pushes the specified cancellation cleanup handler onto
  // the cancellation cleanup stack of the calling thread. When a thread exits or is cancelled,
  // and its cancellation cleanup stack is not empty, the cleanup handlers are invoked with
  // the specified argument in last-in-first-out order from the cancellation cleanup stack
  pthread_cleanup_push(cleanup_handler, dbuf);

  while (1)
  {
    if (host == NULL)
      break;

    // fetch message struct
#ifdef DIMAPISSL
    recv_bytes = SSL_readn( ((struct host *) host)->con, dbuf, BASIC_SIZE);
#else
    recv_bytes = readn( ((struct host *) host)->sockfd, dbuf, BASIC_SIZE);
#endif

    if (recv_bytes == 0) // the peer has gone
      break;
    else if (recv_bytes == -1)
      continue;
    
    if (dbuf->length > DIMAPI_DATA_SIZE)
    {
      printf("Bad IPC message from agent [%s:%d]\n", __FILE__, __LINE__);
      continue;
    }
    
    // fetch any data sent if there is any
    if (dbuf->length - BASIC_SIZE > 0)
    {
#ifdef DIMAPISSL
      recv_bytes = SSL_readn( ((struct host *) host)->con, (char *)dbuf + BASIC_SIZE, dbuf->length - BASIC_SIZE );
#else
      recv_bytes = readn( ((struct host *) host)->sockfd, (char *)dbuf + BASIC_SIZE, dbuf->length - BASIC_SIZE);
#endif

      if(recv_bytes == 0) // the peer has gone
        break;
      else if (recv_bytes == -1)
        continue;
    }

    // FIXME: This seems like a weird place to interperit commands?
    // but stats doesnt poll for new comm data => so we check here. Maybe it should poll?
    if (dbuf->cmd == MAPI_STATS_ACK)
    {
      for (fnode = flist_head(((struct host*)host)->stats); fnode != NULL; fnode = flist_next(fnode))
      {
        stat = (struct mapi_stat *) fnode->data;
        if (strcmp(((struct mapi_stat *) dbuf->data)->dev, stat->dev) == 0)
        {
          strncpy(((struct mapi_stat *)dbuf->data)->hostname, stat->hostname, MAPI_STR_LENGTH);
          memcpy(stat, dbuf->data, sizeof(struct mapi_stat));
          flist_remove(((struct host *)host)->stats, fnode->id);
          break;
        }
      }
      sem_post(&stats_sem);
      continue;
    }
    else if (dbuf->cmd == MAPI_STATS_ERR)
    {
      sem_post(&stats_sem);
      continue;
    }

    hflow = (host_flow *) flist_get(((struct host *) host)->flows, dbuf->fd);

    if (hflow != NULL)
    {
      flow_item = flist_get(*flowlist, hflow->scope_fd);
      rflow = (remote_flowdescr_t *) flow_item->flowdescr;
      if (dbuf->cmd == GET_NEXT_PKT_ACK)
      {
        if (dbuf->length == BASIC_SIZE)
        {
          hflow->pkt->caplen = 0;
        }
        memcpy(hflow->pkt, dbuf->data, dbuf->length-BASIC_SIZE);
        flist_append(rflow->pkt_list, 0, hflow);
        sem_post(&rflow->pkt_sem);
      }
      else
      {
        memcpy(hflow->dbuf, dbuf, dbuf->length);  //place data
        sem_post(&rflow->fd_sem);
      }
    }
    else
    {
      printf("Invalid IPC message, unknown fd %d [%s:%d]\n", dbuf->fd, __FILE__, __LINE__);
      continue;
    }
  }
  pthread_cleanup_pop(1); // pthread_cleanup_pop() function shall remove the routine at the top of the
                          // calling thread's cancellation cleanup stack and invoke it
  return NULL;
}

int mapiipc_remote_init(struct host *h)
//Initializes IPC for dmapi functions
{
  struct hostent *host = gethostbyname(h->hostname);
  struct timeval tv;
  struct sockaddr_in remoteaddr;

#ifdef DIMAPISSL
  SSL_library_init();         // registers the available ciphers and digests
  SSL_load_error_strings();   // registers the error strings for all libcrypto functions and libssl

  if ((h->ctx = SSL_CTX_new(SSLv3_client_method())) == NULL)
  {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  if ((h->con = SSL_new(h->ctx)) == NULL)
  {
    ERR_print_errors_fp(stderr);
    return -1;
  }
#endif

  if ((h->sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    printf("ERROR: socket (%s) [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
    return -1;
  }

  tv.tv_sec=10;		//timeout 10 sec for send
  tv.tv_usec=0;

  if (setsockopt(h->sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(struct timeval)) == -1)
  {
    close(h->sockfd);
    printf("ERROR: Unexpected error on setsockopt() [%s:%d]\n", __FILE__, __LINE__);
    return -1;
  }

  if (host == NULL)
  {
    close(h->sockfd);
    printf("ERROR: Could not determine address for host %s [%s:%d]\n", h->hostname, __FILE__, __LINE__);
    return -1;
  }

  // Construct name of dmapid's socket
  remoteaddr.sin_family = AF_INET;
  remoteaddr.sin_addr = *((struct in_addr *)host->h_addr);
  remoteaddr.sin_port = htons(h->port);

  if (connect(h->sockfd, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr)) < 0)
  {
    close(h->sockfd);
    printf("ERROR: connect failed (%s) [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
    return -1;
  }

#ifdef DIMAPISSL
  if (SSL_set_fd(h->con, h->sockfd) == 0)
  {
    close(h->sockfd);
    ERR_print_errors_fp(stderr);
    return -1;
  }
  if (SSL_connect(h->con) <= 0)
  {
    close(h->sockfd);
    ERR_print_errors_fp(stderr);
    return -1;
  }
#endif

  return 0;
}

void mapiipc_remote_close(struct host *h)
//Releases socket resources
{
  shutdown(h->sockfd, SHUT_RDWR);
  close(h->sockfd);

#ifdef DIMAPISSL
  if (SSL_shutdown(h->con) == -1)  // shut down a TLS/SSL connection
    ERR_print_errors_fp(stderr);

  SSL_free(h->con);   // decrements the reference count of ssl, and removes the SSL structure pointed to by ssl
                      // frees up the allocated memory if the the reference count has reached 0

  if (h->ctx != NULL)
    SSL_CTX_free(h->ctx);   // decrements the reference count of ctx, and removes the SSL_CTX object pointed to by ctx
                            // frees up the allocated memory if the the reference count has reached 0
  ERR_remove_state(0);  // the current thread will have its error queue removed
  ERR_free_strings();  // frees all previously loaded error strings
  EVP_cleanup();    // removes all ciphers and digests from the table
  CRYPTO_cleanup_all_ex_data();  // clean up all allocated state
#endif
}

#ifdef DIMAPISSL
ssize_t SSL_readn(SSL *con, void *vptr, size_t n)
// Read "n" bytes from secure connection.
{
  size_t nleft;
  ssize_t nread;
  char *ptr;
  ptr = vptr;
  nleft = n;

  while (nleft > 0)
  {
    errno = 0;
    if ((nread = SSL_read(con, ptr, nleft)) < 0)
    {
      if (errno == EINTR)
        nread = 0;  /* and call read() again */
      else
        return(-1);
    }
    else if (nread == 0)
      return 0;   /* EOF */

    nleft -= nread;
    ptr += nread;
  }
  return(n - nleft);  /* return >= 0 */
}
#else

ssize_t readn(int fd, void *vptr, size_t n)
// Read "n" bytes from a socket.
{
  size_t nleft;
  ssize_t nread;
  char *ptr;

  ptr = vptr;
  nleft = n;
  while (nleft > 0)
  {
    errno = 0;
    if ((nread = read(fd, ptr, nleft)) < 0)
    {
      if (errno == EINTR)
        nread = 0;  // and call read() again
      else
        return(-1);
    }
    else if (nread == 0)
      return 0;  // EOF

    nleft -= nread;
    ptr += nread;
  }
  
  return (n - nleft);  // return >= 0
}
#endif
