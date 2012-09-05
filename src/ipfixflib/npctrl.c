/* Jon Kåre Hellan, November 2003, based on */
/*
 *  Copyright (C) 2002-03 Luca Deri <deri@ntop.org>
 *
 *  			  http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
************************************************************************

History:


************************************************************************
*/

#include "nprobe.h"
#include "nprobe-priv.h"
#include "ifp-priv.h"
#include "npctrl.h"

#define MAX_SAMPLE_RATE    ((u_short)-1)

/* ****************************************************** */

/* ****************************************************** */

static char *
printPayloadValue(u_char payloadExportType) {
  switch(payloadExportType) {
  case 0:
    return("no payload");
    break;
  case 1:
    return("full payload");
    break;
  case 2:
    return("payload only with SYN set");
    break;
  default:
    return("??");
  }
}

/* ****************************************************** */
void
ipfix_init(void)
{
  npInitGlobals();
}

void *
ipfix_start(void *mapi_ctxt, ifp_rec_type_t rec_type, 
	    char *transport_name, char *stringTemplate,
	    struct mapid_hw_info *hwinfo)
{
  int i, mallocSize;
  np_ctxt_t *npctxt = NULL;
  np_list_t *elt;
  char *addr=NULL, *port=NULL;

  /* Set defaults */
  npctxt = npInitContext();
  if (!npctxt)
	  return NULL;
  npctxt->mapi_ctxt = mapi_ctxt;
  npctxt->usePcap = 0;
  elt = calloc(1, sizeof (np_list_t));
  if (!elt)
	  return NULL;
  elt->data = npctxt;
  if (np_contexts)
    elt->next = np_contexts;
  np_contexts = elt;

  npctxt->useNetFlow = 1;
  npctxt->fileexportHandle = NULL;
  npctxt->fileexportName   = NULL;

  npctxt->hwinfo = hwinfo;
  npctxt->initialPktsDropped = npctxt->hwinfo->pkt_drop;

  switch (rec_type) {
  case rec_type_ipfix:
    npctxt->netFlowVersion = 0x0a;
    break;
  case rec_type_nf_v5:
    npctxt->netFlowVersion = 5;
    break;
  case rec_type_nf_v9:
    npctxt->netFlowVersion = 9;
    break;
  default:
    break;
  }
  if (!transport_name || strlen (transport_name) == 0 ||
      strcmp (transport_name, "SHMEM") == 0) {
    /* Shared memory transport */
  } else if(strncmp(transport_name,"file:",5) == 0) {
    /* FILE transport */
    npctxt->fileexportName = strdup(transport_name+5);
    npctxt->fileexportHandle = fopen(npctxt->fileexportName,"wb");
    if(!npctxt->fileexportHandle) {
      	traceEvent(npctxt, TRACE_ERROR, "ERROR: output file open failed for %s", npctxt->fileexportName);
    }
  } else {
    addr = strdup(transport_name);
    port = NULL;
    
    for (i = strlen (addr); i >= 0; i--) {
      if (addr[i] == ':') {
	addr[i] = '\0';
	port = &addr[i+1];
	break;
      }
    }
    if (port != NULL && initNetFlow(npctxt, addr, atoi(port)) == 0) {
      /* Successfully initialized UDP export */
    } else {
      if (port == NULL)
	traceEvent(npctxt, TRACE_ERROR, "ERROR: invalid address %s", transport_name);
      /* Will revert to shared memory export */
    }
  }
  if (npctxt->numCollectors == 0)
    traceEvent(npctxt, TRACE_INFO, "Exporting flows using MAPI shared memory");
  if(npctxt->fileexportHandle != NULL)
    traceEvent(npctxt, TRACE_INFO, "Exporting flows using file '%s'",npctxt->fileexportName);
  
  
  npctxt->hash = NULL;
  npctxt->bufferLen = 0;
  npctxt->shutdownInProgress = 0;

  createCondvar(&npctxt->exportQueueCondvar);
  pthread_mutex_init(&exportMutex, NULL);
  pthread_mutex_init(&purgedBucketsMutex, NULL);

  for(i=0; i<MAX_HASH_MUTEXES; i++)
    pthread_mutex_init(&hashMutex[i], NULL);

  pthread_create(&npctxt->dequeueThread, NULL, dequeueBucketToExport, npctxt);
  pthread_create(&npctxt->walkHashThread, NULL, hashWalker, npctxt);

  npctxt->npBuffer = (unsigned char*)malloc(NETFLOW_MAX_BUFFER_LEN);

  // Compile the template to send data in
  // Only used for netflow version 9, and ipfix. IPFix differs slightly in how
  // templates are generated (enterprise ID).
  if(npctxt->netFlowVersion == 9 || npctxt->netFlowVersion == 0x0a)
    compileTemplate(npctxt, stringTemplate, npctxt->v9TemplateList, TEMPLATE_LIST_LEN);

  if(npctxt->netFlowVersion == 5) {
    npctxt->maxNumFlowsPerPacket = V5FLOWS_PER_PAK;
    if(npctxt->maxNumFlowsPerPacket < npctxt->minNumFlowsPerPacket)
      npctxt->minNumFlowsPerPacket = npctxt->maxNumFlowsPerPacket;
  }

  if(npctxt->npBuffer == NULL) {
    traceEvent(npctxt, TRACE_ERROR, "ERROR: not enough memory\n");
    return NULL;
  }

  /* mapi-based sniffing */
  mallocSize = sizeof(HashBucket*)*npctxt->hashSize;
  npctxt->hash = (HashBucket**)calloc(1, mallocSize);
  if(npctxt->hash == NULL || npctxt->netFlowDest == NULL) {
    traceEvent(npctxt, TRACE_ERROR, "ERROR: not enough memory\n");
    return NULL;
  }

  npctxt->purgedBuckets = NULL;
  
  npInitCounters(npctxt);

  traceEvent(npctxt, TRACE_INFO, "The flows hash has %d buckets", npctxt->hashSize);
  traceEvent(npctxt, TRACE_INFO, "Flows older than %d seconds will be exported", npctxt->lifetimeTimeout);
  traceEvent(npctxt, TRACE_INFO, "Flows inactive for at least %d seconds will be exported", npctxt->idleTimeout);
  traceEvent(npctxt, TRACE_INFO, "Expired flows will be checked every %d seconds",
	     npctxt->scanCycle);
  traceEvent(npctxt, TRACE_INFO, "Expired flows will not be queued for more than %d seconds", npctxt->sendTimeout);

  if((engineType != 0) || (engineId != 0))
    traceEvent(npctxt, TRACE_INFO, "Exported flows with engineType=%d and engineId=%d", engineType, engineId);

  if(npctxt->minFlowPkts > 1)
    traceEvent(npctxt, TRACE_INFO, "TCP flows %u packets or less will not be emitted", npctxt->minFlowPkts - 1);

  if(npctxt->ignoreTcpUdpPorts)
    traceEvent(npctxt, TRACE_INFO, "UDP/TCP ports will be ignored and set to 0.");

  if(npctxt->flowExportDelay > 0)
    traceEvent(npctxt, TRACE_INFO, "The minimum intra-flow delay is of at least %d us", npctxt->flowExportDelay);

  if(npctxt->numCollectors > 1)
    traceEvent(npctxt, TRACE_INFO, "Flows will be sent to the defined collectors in round robin.");

  if(npctxt->useNetFlow)
    traceEvent(npctxt, TRACE_INFO, "Flows will be emitted in NetFlow v%d format", 
	       (int)npctxt->netFlowVersion);
  else {
    traceEvent(npctxt, TRACE_INFO, "Flows will be emitted in nFlow v1 format");
    if(npctxt->maxPayloadLen) {
      traceEvent(npctxt, TRACE_INFO, "Max payload length set to %d bytes", 
		 npctxt->maxPayloadLen);
      traceEvent(npctxt, TRACE_INFO, "Payload export policy (-x) for TCP:   %s",
		 printPayloadValue(npctxt->tcpPayloadExport));
      traceEvent(npctxt, TRACE_INFO, "Payload export policy (-x) for UDP:   %s",
		 printPayloadValue(npctxt->udpPayloadExport));
      traceEvent(npctxt, TRACE_INFO, "Payload export policy (-x) for ICMP:  %s",
		 printPayloadValue(npctxt->icmpPayloadExport));
      traceEvent(npctxt, TRACE_INFO, "Payload export policy (-x) for OTHER: %s",
		 printPayloadValue(npctxt->otherPayloadExport));
    } else
      traceEvent(npctxt, TRACE_INFO, "Payload will not be exported in emitted flows");
  }

  if(npctxt->sampleRate > 0)
    traceEvent(npctxt, TRACE_INFO, "Sampling packets at 1:%d rate", 
	       npctxt->sampleRate);

  return (void *) npctxt;
}

void
ipfix_shutdown(void *ctxt)
{
  np_ctxt_t *npctxt = (np_ctxt_t *)ctxt;
  np_list_t *elt, *prev;

  shutdownInstance(npctxt);
  for (prev = NULL, elt = np_contexts; elt; prev = elt, elt = elt->next) {
    if (elt->data == ctxt) {
      if (prev) {
	prev->next = elt->next;
      } else {
	np_contexts = elt->next;
      }
      free(elt);
      break;
    }
  }
  free(ctxt);
}
