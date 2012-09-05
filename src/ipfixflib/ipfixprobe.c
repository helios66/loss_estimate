#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "cbuf.h"
#include "ipfixlib.h"
#include "ifp-priv.h"
#include "npktproc.h"
#include "npctrl.h"
#include "debug.h"
#include "mapi_errors.h"

#define IFP_NAME "FLOW_REPORT"
#define IFP_FIFO_SIZE 512

typedef struct {
  void *npctxt;
} ifp_idata_t;

typedef struct {
  mapidflib_function_instance_t *instance; //Function instance
  unsigned long read_ptr; //Pointer to the next record that can be read
  unsigned long write_ptr; //Pointer to where the next packet can be written
  unsigned long next_recno; // Record numner of next record
  int fifo_lock;
  ifp_dgram_t rbuf[IFP_FIFO_SIZE]; /* Flow record buffer */
  unsigned bufsize;  //Size of buffer
} ifp_t;

extern mapidflib_function_def_t* ipfixp_get_funct_info();

static struct {
  char          *name;
  ifp_rec_type_t rtype;
} rec_types[] = {
  { "IPFIX",      rec_type_ipfix },
  { "NETFLOW_V5", rec_type_nf_v5 },
  { "NETFLOW_V9", rec_type_nf_v9 }
};


/* 
 * Create and initialize the per flow instance.
 */
/*static int 
ifp_instance(mapidflib_function_instance_t *instance,
	     flist_t *flist,
	     mapidflib_flow_mod_t *flow_mod, function_manipulation_t* manip)
{
  //TODO: Verify arguments
  return 0;
};*/

static int ifp_init(mapidflib_function_instance_t *fi,
	 MAPI_UNUSED int fd)
{
  ifp_t *ifp;
  ifp_idata_t *idata;
  mapiFunctArg* fargs=fi->args;
  char *rec_type_name;
  char *transport_name;
  char *key_template;
  char *record_template;
  ifp_rec_type_t rec_type = rec_type_undef;
  int i;
  static int initialized = 0;

  DEBUG_CMD(Debug_Message("IFP: init()"));

  rec_type_name   = getargstr(&fargs);
  transport_name  = getargstr(&fargs);
  key_template    = getargstr(&fargs);
  record_template = getargstr(&fargs);


  if (rec_type_name == NULL) {
    rec_type = rec_type_ipfix;
  } else {
    for(i = 0; i < (int) (sizeof rec_types / sizeof rec_types[0]); i++) {
      if (strcmp(rec_types[i].name, rec_type_name) == 0)
	rec_type = rec_types[i].rtype;
    }
  }
  if (rec_type == rec_type_undef) {
    DEBUG_CMD(Debug_Message("IFP: init: Illegal record type %s", rec_type_name));
    return  MFUNCT_INVALID_ARGUMENT;
  }

  DEBUG_CMD(Debug_Message("IFP: init: rec_type_name=%s", rec_type_name));
  DEBUG_CMD(Debug_Message("IFP: init: rec_type=%d", rec_type));
  DEBUG_CMD(Debug_Message("IFP: init: transport_name=%s", transport_name));
  DEBUG_CMD(Debug_Message("IFP: init: key_template=%sd", key_template));
  DEBUG_CMD(Debug_Message("IFP: init: record_template=%s", record_template));
  
  /* Allocate shared data */

  idata = calloc(1, sizeof(ifp_idata_t));
  fi->internal_data = (mapidflib_function_instance_t *) idata;

  ifp = fi->result.data;
  ifp->fifo_lock = 0;
  
  while(__sync_lock_test_and_set(&(ifp->fifo_lock),1));
  
  ifp->instance = fi;
  ifp->read_ptr = 0;
  ifp->write_ptr = 0;
  ifp->next_recno = 0;
  ifp->bufsize = IFP_FIFO_SIZE;

  ifp->fifo_lock = 0;

  if (!initialized) {
    ipfix_init();
    initialized = 1;
  }
  idata->npctxt = ipfix_start((void *) ifp, 
			      rec_type, transport_name, record_template, fi->hwinfo);

  DEBUG_CMD(Debug_Message("ifp_init: idata=0x%x", (int) idata));
  DEBUG_CMD(Debug_Message("ifp_init: idata->npctxt=0x%x", (int) idata->npctxt));
  
  return 0;
}

/* 
 * Ring buffer may be full. Two cases:
 * - online flow. We just have to drop the flows on the floor, or the 
 *   backlog is likely to keep building up.
 * - offline flow. Wait and try again.
 */
void 
ifp_write_shm(const void *ctxt, const void *buffer, u_int32_t buf_len) 
{
  static unsigned maxlen = 0;
  ifp_dgram_t *rec;
  unsigned new_write;
  int done = FALSE;
  ifp_t *ifp = (ifp_t *) ctxt;
  
  if (buf_len > maxlen) {
    maxlen = buf_len;
    DEBUG_CMD(Debug_Message("ifp_write_shm: buf_len=%d", buf_len));
  }
	
  while (!done) {
    while(__sync_lock_test_and_set(&(ifp->fifo_lock),1));
    new_write = ifp->write_ptr + 1;
    if (new_write >= IFP_FIFO_SIZE)
      new_write = 0;
    if (new_write == ifp->read_ptr) {
      if (ifp->instance->hwinfo->offline == 0) {
	DEBUG_CMD(Debug_Message("Flow record no. %ld - %d bytes long dropped", ifp->next_recno, buf_len));
	done = TRUE;
      }
    } else {
      rec = (ifp_dgram_t*) (ifp->rbuf + ifp->write_ptr);
      rec->recno = ifp->next_recno;
      rec->size  = buf_len;
      memcpy(rec->bytes, buffer, buf_len);
      ifp->write_ptr = new_write;
      done = TRUE;
    }
    ifp->fifo_lock = 0;
    if (!done) {
      /* Wait and try again */
      struct timeval timeout;
      timeout.tv_sec = 0;
      timeout.tv_usec = 10000;
      
      select (0, NULL, NULL, NULL, &timeout);
    }
  }
  ifp->next_recno++;
}

mapi_offline_device_status_t
ifp_get_offline_device_status(const void *ctxt)
{
  ifp_t *ifp = (ifp_t *) ctxt;

  if (ifp->instance->hwinfo != NULL)
    return ifp->instance->hwinfo->offline;
  else
    return DEVICE_ONLINE; 	/* You've got to return *something* */
}

static int 
ifp_process(mapidflib_function_instance_t *instance,
	    MAPI_UNUSED unsigned char* dev_pkt,
	    unsigned char* link_pkt,
	    mapid_pkthdr_t* pkt_head)
{
  nprobeProcessPacket(((ifp_idata_t *)instance->internal_data)->npctxt, 
		      pkt_head, link_pkt);
  return 1;
}

static int
ifp_get_result(mapidflib_function_instance_t *instance,
	       mapidflib_result_t **res)
{
  (*res)=&instance->result;
  return 0;
}

static int
ifp_cleanup(mapidflib_function_instance_t *instance) 
{
  ifp_idata_t *idata = NULL;

  DEBUG_CMD(Debug_Message("IFP: cleanup(0x%x)", (int) instance));
  // If this fails it means someone has already cleaned-up
  idata = (ifp_idata_t *)instance->internal_data;
  if (idata) {
    ipfix_shutdown(idata->npctxt);
    free (idata);
    instance->internal_data = NULL;
  }

  DEBUG_CMD(Debug_Message("IFP: cleanup(0x%x) finished",(int) instance));
  return 1;
}

static int 
ifp_client_read_result(mapidflib_function_instance_t* instance,
		       mapi_result_t *res)
{
  ifp_t *ifp = (ifp_t *)instance->result.data;
  ifp_dgram_t *rec = NULL;
  int done = FALSE;

  while (!done) {
    //wait for record(spinlock blocks when no records are ready in the buffer)
    while(__sync_lock_test_and_set(&(ifp->fifo_lock),1));
  
    if (ifp->read_ptr != ifp->write_ptr) {
      // Copy flow record from kmem
      rec = (ifp_dgram_t*) (ifp->rbuf + ifp->read_ptr);
      ifp->read_ptr++;
  
      if(ifp->read_ptr >= IFP_FIFO_SIZE)
	ifp->read_ptr=0;
      done = TRUE;
    }
    ifp->fifo_lock = 0;
    if (!done) {
      /* Pause during busy waiting */
      struct timeval timeout;
      timeout.tv_sec = 0;
      timeout.tv_usec = 10000;
      
      select (0, NULL, NULL, NULL, &timeout);
    }
  }
  
  res->res = rec;
  res->size = sizeof *rec;
  
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  IFP_NAME,
  "IPFIX (NetFlow v9) probe",
  "ssss",                         /* Argdescr */
  MAPI_DEVICE_ALL,
  MAPIRES_SHM,
  sizeof(ifp_t), //shm size
  0, //modifies packets
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  NULL, //ifp_instance,
  ifp_init,
  ifp_process,
  ifp_get_result,
 	NULL,
  ifp_cleanup,
  NULL, //client_init
  ifp_client_read_result,
  NULL  //client_cleanup
};



mapidflib_function_def_t* ipfixp_get_funct_info() {
  return &finfo;
};
