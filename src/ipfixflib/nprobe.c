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

1.0    [06/02]        Initial release
1.3    [07/02]        First public release
2.0    [01/03]        Full rewrite (see manual)
2.0.1  [02/03]        Added -P
2.0.2  [02/03]        Added -C parameter to -P for storing flows in compressed format
2.0.3  [02/03]        Added -E for specifying the NetFlow engine
2.2.90 [06/03]        Added nFlow-rewised/NetFlowv9
2.2.91 [09/03]        Major code rewrite after debugging at University of Texas

Modified -p
Added -S

************************************************************************
*/

#include "debug.h"
#include "nprobe.h"
#include "nprobe-priv.h"
#include "ifp-priv.h"
#include "parseconf.h"
#include "debug.h"

#define DISPLAY_TIME               30

#define BLANK_SPACES               "                     "
#define TCP_PROTOCOL               0x06

#define DEBUG_JK

/* #undef DEBUG_LEAK */
#define STAT_INTERVAL 30

#define TIME_PROTECTION

/* *********** Globals ******************* */

np_list_t *np_contexts;
int      nInstances = 0;

u_int hashDebug = 0;
u_int64_t totExports = 0;

/* Threads */
pthread_mutex_t exportMutex, purgedBucketsMutex, hashMutex[MAX_HASH_MUTEXES];

/* ****************************************************** */

/* Forward */
static int exportBucketToNetflow(np_ctxt_t *npctxt, HashBucket *myBucket, 
				 int direction);
static int exportBucketToNetflowV5(np_ctxt_t *npctxt, HashBucket *myBucket, 
				   int direction);
static int exportBucketToNetflowV9(np_ctxt_t *npctxt, HashBucket *myBucket, 
				   int direction);
static int exportBucketTonFlow(np_ctxt_t *npctxt, HashBucket *myBucket, 
			       int direction);
static void checkExportQueuedFlows(np_ctxt_t *npctxt, int forceExport);
static void checknFlowExport(np_ctxt_t *npctxt, int forceExport);
static void printStats(np_ctxt_t *npctxt);


/* ****************************************************** */

static void 
exportBucket(np_ctxt_t *npctxt, HashBucket *myBucket) 
{
  int rc = 0;

  if(myBucket->pktSent >= npctxt->minFlowPkts) {
    if(npctxt->useNetFlow)
      rc = exportBucketToNetflow(npctxt, myBucket, 0 /* src -> dst */);
    else
      rc = exportBucketTonFlow(npctxt, myBucket, 0 /* src -> dst */);

    if(rc > 0)
      npctxt->totFlows++;
  }

  if(myBucket->src2dstPayload != NULL) {
    free(myBucket->src2dstPayload);
    myBucket->src2dstPayload = NULL;
  }

  /* *********************** */

  if(myBucket->bytesRcvd > 0) {
    if(myBucket->pktRcvd >= npctxt->minFlowPkts) {
      if(npctxt->useNetFlow)
	rc = exportBucketToNetflow(npctxt, myBucket, 1 /* dst -> src */);
      else
	rc = exportBucketTonFlow(npctxt, myBucket, 1 /* dst -> src */);

      if(rc > 0)
	npctxt->totFlows++;
    }

    if(myBucket->dst2srcPayload != NULL) {
      free(myBucket->dst2srcPayload);
      myBucket->dst2srcPayload = NULL;
    }
  }
  if(myBucket->sip_call_id != NULL) {
    free(myBucket->sip_call_id);
    myBucket->sip_call_id = NULL;
  }
  if (myBucket->rtp_a_stat != NULL) {
    free(myBucket->rtp_a_stat);
    myBucket->rtp_a_stat = NULL;
  }
  if (myBucket->rtp_b_stat != NULL) {
    free(myBucket->rtp_b_stat);
    myBucket->rtp_b_stat = NULL;
  }
  if (myBucket->mpegts_stat != NULL) {
    free(myBucket->mpegts_stat);
    myBucket->mpegts_stat = NULL;
  }
}

/* ****************************************************** */

void queueBucketToExport(np_ctxt_t *npctxt, HashBucket *myBucket) {
  pthread_mutex_lock(&exportMutex);
  /*  addToList(myBucket, &npctxt->exportQueue); */
  addToListEnd(myBucket, &npctxt->exportQueue, &npctxt->exportQueueEnd);
  myBucket->time_exported = time(NULL);
  npctxt->exportBucketsLen++;
  pthread_mutex_unlock(&exportMutex);
  /*signalCondvar(&npctxt->exportQueueCondvar); */
  /*  NOTE: signalling is done in calling procedure, in order to */
  /*   signal only once, after all entries have been enqueued. */
}

/* ****************************************************** */

void* 
dequeueBucketToExport(void* ctxt) 
{
  np_ctxt_t *npctxt = (np_ctxt_t *)ctxt;
  u_int32_t timediff;

  while(1) {
    if(npctxt->exportQueue == NULL) {
      if(!npctxt->shutdownInProgress)
	waitCondvar(&npctxt->exportQueueCondvar);
      else
	break;
    }

    if(npctxt->exportQueue != NULL) {
      HashBucket *myBucket;

      /* This is the only place where we remove from export queue, so no race here */
      pthread_mutex_lock(&exportMutex);
      myBucket = getListHead(&npctxt->exportQueue);
      if(npctxt->exportQueue==NULL)
	npctxt->exportQueueEnd = NULL;
      npctxt->exportBucketsLen--;
      pthread_mutex_unlock(&exportMutex);

      /* Export bucket */
      timediff = time(NULL)-myBucket->time_exported;
      if(timediff <= npctxt->maxExportQueueLatency) {      
	exportBucket(npctxt, myBucket);
      } else {
	if(myBucket->pktRcvd > 0)
	  npctxt->notsent_flows = npctxt->notsent_flows + 2ull;
	else
	  npctxt->notsent_flows = npctxt->notsent_flows + 1ull;
	npctxt->notsent_pkts   = npctxt->notsent_pkts + (u_int64_t)myBucket->pktSent + (u_int64_t)myBucket->pktRcvd;
	npctxt->notsent_octets = npctxt->notsent_octets+(u_int64_t)myBucket->bytesSent+(u_int64_t)myBucket->bytesRcvd; 
      }

      /* Recycle bucket */
      pthread_mutex_lock(&purgedBucketsMutex);
      addToList(myBucket, &npctxt->purgedBuckets);
      npctxt->purgedBucketsLen++;
      pthread_mutex_unlock(&purgedBucketsMutex);
    }
  }

  traceEvent(npctxt, TRACE_INFO, "Export thread terminated [exportQueue=%x]\n", npctxt->exportQueue);
  return(NULL);
}

/* ****************************************************** */

/*
  From the tests carried on, the very best approach
  is to have a periodic thread that scans for expired
  flows.
*/
void* 
hashWalker(void* ctxt) {
  np_ctxt_t *npctxt = (np_ctxt_t *)ctxt;
  u_int numSlots = 0;
  mapi_offline_device_status_t offstat;

  /* Wait until all the data structures have been allocated */
  while(npctxt->hash == NULL) ntop_sleep(1);

  for(;npctxt->shutdownInProgress == 0;) {
    offstat = ifp_get_offline_device_status (npctxt->mapi_ctxt);
    walkHash(npctxt, offstat >= DEVICE_FINISHED);
    if(++numSlots >= npctxt->hashSize) {
      int activeBuckets = npctxt->bucketsAllocated-(npctxt->purgedBucketsLen+npctxt->exportBucketsLen);
      u_int32_t freeBucketsThreshold = activeBuckets*.1; /* 10% of activeBuckets */

      if(npctxt->purgedBucketsLen > freeBucketsThreshold) {
	/* Too many buckets: let's free some of them */
	while(npctxt->purgedBuckets && (npctxt->purgedBucketsLen > 0) && (freeBucketsThreshold > 0)) {
	  HashBucket *bkt;

	  pthread_mutex_lock(&purgedBucketsMutex);
	  /* Get the head, but check first that it hasn't been removed by another thread */
	  if (npctxt->purgedBuckets && (npctxt->purgedBucketsLen > 0) && (freeBucketsThreshold > 0)) {
	    bkt = getListHead(&npctxt->purgedBuckets);
	    npctxt->purgedBucketsLen--, npctxt->bucketsAllocated--;
	  }
	  pthread_mutex_unlock(&purgedBucketsMutex);

	  /* Free the head */
	  free(bkt);
	  freeBucketsThreshold--;
	}
      }

      printStats(npctxt);
      numSlots = 0;
      if (npctxt->shutdownInProgress == 0)
	ntop_sleep(npctxt->scanCycle);
    }
  }

  traceEvent(npctxt, TRACE_INFO, "Hash walker thread terminated\n");
  return(NULL);
}

#ifdef DEBUG_LEAK
static int getListLength(HashBucket *list)
{
  int count = 0;
  HashBucket *ptr;

  for (ptr = list; ptr; ptr = ptr->next) {
    count++;
  }
  return count;
}

static int countActiveBuckets(np_ctxt_t *npctxt)
{
  u_int i, count = 0;
 
  for (i = 0; i < npctxt->hashSize; i++) {
    u_int mutexIdx = i % MAX_HASH_MUTEXES;
    pthread_mutex_lock(&hashMutex[mutexIdx]);
    count += getListLength(npctxt->hash[i]);
    pthread_mutex_unlock(&hashMutex[mutexIdx]);
  }
  return count;
}
#endif

/* ****************************************************** */

static void 
printStats(np_ctxt_t *npctxt) 
{
  struct pcap_stat pcapStat;
  time_t now = time(NULL), nowDiff;
  char buf[32];

  nowDiff = now - (npctxt->initialSniffTime >> 32);
  npctxt->statSkipCnt++;


  /* Wait at least 10 seconds */
  if((npctxt->statSkipCnt < npctxt->statInterval) ||(nowDiff < 10) || (npctxt->totalPkts == 0)) return;

  if(npctxt->traceMode) {
    npctxt->statSkipCnt = 0;
    traceEvent(npctxt, TRACE_INFO, "Average traffic: [%.1f pkt/sec][%s/sec]",
	       (float)npctxt->totalPkts/nowDiff,
	       formatTraffic((float)(8*npctxt->totalBytes)/(float)nowDiff, 1, buf));
    
    nowDiff = now-npctxt->lastSample;
    traceEvent(npctxt, TRACE_INFO, "Current traffic: [%.1f pkt/sec][%s/sec]",
	       (float)npctxt->currentPkts/nowDiff,
	       formatTraffic((float)(8*npctxt->currentBytes)/(float)nowDiff, 1, buf));
    npctxt->lastSample = now;
    npctxt->currentBytes = npctxt->currentPkts = 0;

    traceEvent(npctxt, TRACE_INFO, "Current flow export rate: [%.1f flows/sec]",
	       (float)npctxt->totFlows/nowDiff);
    npctxt->totFlows = 0;

#ifdef DEBUG_LEAK
    {
      int activeCounted      = countActiveBuckets(npctxt);
      int activeAccountedFor = npctxt->bucketsAllocated-(npctxt->purgedBucketsLen+npctxt->exportBucketsLen);

      traceEvent(npctxt, TRACE_INFO, "Buckets: [active=%d(counted=%d,lost=%d)][allocated=%d][free=%d][toBeExported=%d][frags=%d]",
		 activeAccountedFor,
		 activeCounted,
		 activeAccountedFor -activeCounted,
		 npctxt->bucketsAllocated, npctxt->purgedBucketsLen, 
		 npctxt->exportBucketsLen,
		 npctxt->fragmentListLen);
    }
#else
    traceEvent(npctxt, TRACE_INFO, "Buckets: [active=%d][allocated=%d][free=%d][toBeExported=%d][frags=%d]",
	       npctxt->bucketsAllocated-(npctxt->purgedBucketsLen+npctxt->exportBucketsLen),
	       npctxt->bucketsAllocated, npctxt->purgedBucketsLen, 
	       npctxt->exportBucketsLen,
	       npctxt->fragmentListLen);
#endif
#ifdef DEBUG_JK
    traceEvent(npctxt, TRACE_INFO, "Flow expiry reasons: [idle=%d][active=%d][eof=%d][forced=%d][cacheexpired=%d]", 
	       npctxt->endCntIdle,
	       npctxt->endCntActive,
	       npctxt->endCntEof,
	       npctxt->endCntForced,
	       npctxt->endCntCacheExpired);
    traceEvent(npctxt, TRACE_INFO, "Srv.class: [cached=%d][uncached=%d][torrent=%d][rtp=%d]", 
	     npctxt->cacheCnt,
	     npctxt->uncacheCnt,
	     npctxt->torrentCnt,
	     npctxt->rtpCnt);
    traceEvent(npctxt, TRACE_INFO, "Timeouts: [idle=%d],[lifetime=%d], Offline: [%d]",
	     npctxt->idleTimeout, npctxt->lifetimeTimeout, 
	     ifp_get_offline_device_status (npctxt->mapi_ctxt));
    npctxt->endCntIdle         = 0;
    npctxt->endCntActive       = 0;
    npctxt->endCntEof          = 0;
    npctxt->endCntForced       = 0;
    npctxt->endCntCacheExpired = 0;
    npctxt->cacheCnt           = 0;
    npctxt->uncacheCnt         = 0;
    npctxt->torrentCnt         = 0;
    npctxt->rtpCnt             = 0;
#endif
  }
  
  if(npctxt->traceMode) {
    traceEvent(npctxt, TRACE_INFO, "Num Packets: %llu (max/avg bucket search: %d/%.1f)",
	       npctxt->totalPkts, npctxt->maxBucketSearch, 
	       ((double)npctxt->sumBucketSearch)/npctxt->totalPkts);
  } else {
    if(npctxt->maxBucketSearch > npctxt->lastMaxBucketSearch) {
      traceEvent(npctxt, TRACE_INFO, 
		 "Max/avg bucket search: %d/%.1f slots (for better performance a larger value for hashSize)",
		 npctxt->maxBucketSearch,
		 ((double)npctxt->sumBucketSearch)/npctxt->totalPkts);
      npctxt->lastMaxBucketSearch = npctxt->maxBucketSearch;
    }
  }

  if(npctxt->notsent_flows > 0ull) {
    traceEvent(npctxt, TRACE_INFO, "Total non-exported flows due to congestion: %llu", npctxt->notsent_flows);
  }

  npctxt->maxBucketSearch = 0; /* reset */

  if (npctxt->usePcap) {
    if(pcap_stats(npctxt->pcapPtr, &pcapStat) >= 0) {
      if(npctxt->traceMode) {
	traceEvent(npctxt, TRACE_INFO, "%u pkts rcvd/%u pkts dropped",
		   pcapStat.ps_recv, pcapStat.ps_drop);
      }
    }
  } else if(npctxt->hwinfo != NULL) {
    double totalPkts = npctxt->totalPkts==0?1.0:npctxt->totalPkts;
    unsigned long droppedPkts = pktsDropped(npctxt) > 0UL;
    if(droppedPkts > 0UL) {
      double d = (double)droppedPkts*100.0/(double)(droppedPkts + totalPkts);
      traceEvent(npctxt, TRACE_INFO, "Packets dropped: %lu (%3.2f%%)", 
		 (u_long)droppedPkts, d);
    }
  }
}

/* ****************************************************** */

static int 
resolveIpV4Address(np_ctxt_t *npctxt, char *addr, int port) 
{
  struct hostent *hostAddr;
  struct in_addr dstAddr;
  
  if((hostAddr = gethostbyname(addr)) == NULL) {
    traceEvent(npctxt, TRACE_INFO, "Unable to resolve address '%s'\n", addr);
    return(-1);
  }
  
  memcpy(&dstAddr.s_addr, hostAddr->h_addr_list[0], hostAddr->h_length);
  npctxt->netFlowDest[npctxt->numCollectors].isV6 = 0;
  npctxt->netFlowDest[npctxt->numCollectors].u.v4Address.sin_addr.s_addr
	  = dstAddr.s_addr;
  npctxt->netFlowDest[npctxt->numCollectors].u.v4Address.sin_family 
    = AF_INET;
  npctxt->netFlowDest[npctxt->numCollectors].u.v4Address.sin_port 
    = (int)htons(port);
  
  return(0);
}

/* ****************************************************** */

#ifndef IPV4_ONLY

static int 
resolveIpV6Address(np_ctxt_t *npctxt, char *addr, int port) 
{
  int errnum;
  struct addrinfo hints, *res;
  
  if((npctxt->useIpV6 == 0) || strstr(addr, "."))
    return(resolveIpV4Address(npctxt, addr, port));

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  errnum = getaddrinfo(addr, NULL, &hints, &res);
  if(errnum != 0) {
    traceEvent(npctxt, TRACE_INFO, "Unable to resolve address '%s' [error=%d]\n", addr, errnum);
    return(-1);
  }
  
  memset(&npctxt->netFlowDest[npctxt->numCollectors], 0,
	 sizeof(npctxt->netFlowDest[npctxt->numCollectors]));
  npctxt->netFlowDest[npctxt->numCollectors].isV6 = 1;
  npctxt->netFlowDest[npctxt->numCollectors].u.v6Address.sin6_family
    = res->ai_family;
  npctxt->netFlowDest[npctxt->numCollectors].u.v6Address.sin6_flowinfo
    = 0;
  npctxt->netFlowDest[npctxt->numCollectors].u.v6Address.sin6_port
    = (int)htons(port);
  memcpy(&npctxt->netFlowDest[npctxt->numCollectors].u.v6Address.sin6_addr, 
	 res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);
  return(0);
}

#endif

/* ****************************************************** */

int initNetFlow(np_ctxt_t *npctxt, char* addr, int port) {
  int sockopt = 1, rc;

  if(npctxt->numCollectors >= MAX_NUM_COLLECTORS) {
    traceEvent(npctxt, TRACE_INFO,
	       "Unable to define further collector address (max %d collectors allowed)\n",
	       MAX_NUM_COLLECTORS);
    return(-1);
  }

  if(npctxt->netFlowOutSocket == -1) {
#ifdef IPV4_ONLY
    npctxt->netFlowOutSocket = socket(AF_INET, SOCK_DGRAM, 0);
#else
    npctxt->netFlowOutSocket = socket(AF_INET6, SOCK_DGRAM, 0);

    if(npctxt->netFlowOutSocket == -1) {
      npctxt->useIpV6          = 0; /* No IPv6 ? */
      npctxt->netFlowOutSocket = socket(AF_INET, SOCK_DGRAM, 0);
    }

#endif
    setsockopt(npctxt->netFlowOutSocket, SOL_SOCKET, SO_REUSEADDR,
	       (char *)&sockopt, sizeof(sockopt));
  }

  if(npctxt->netFlowOutSocket == -1) {
    traceEvent(npctxt, TRACE_INFO, "Fatal error while creating socket (%s)", strerror(errno));
    return(-1);
  }

  /* ****************************** */

#ifdef IPV4_ONLY
  rc = resolveIpV4Address(npctxt, addr, port);
#else
  rc = resolveIpV6Address(npctxt, addr, port);
#endif

  if(rc != 0)
    return(-1);

  npctxt->numCollectors++;

  /* ****************************** */
  
  if(strstr(addr, ":"))
    traceEvent(npctxt, TRACE_INFO, "Exporting flows towards [%s]:%d", addr, port);
  else
    traceEvent(npctxt, TRACE_INFO, "Exporting flows towards %s:%d", addr, port);

  return(0);
}

/* ****************************************************** */

static void 
sendNetFlow(np_ctxt_t *npctxt, const void *buffer, u_int32_t bufferLength, 
	    u_char lastFlow) 
{
  u_int32_t rc;

  npctxt->exportedOctetTotalCount   = npctxt->exportedOctetTotalCount + (u_int64_t)bufferLength;
  npctxt->exportedMessageTotalCount = npctxt->exportedMessageTotalCount + (u_int64_t)1;

#ifdef DEBUG_EXPORT
  traceEvent(npctxt, TRACE_INFO, "==>> sendNetFlow(%d)", bufferLength);
#endif

  /*
    This delay is used to slow down export rate as some
    collectors might not be able to catch up with nProbe
  */
  if((npctxt->flowExportDelay > 0) && (!lastFlow)) {
#ifndef WIN32
    /*struct timespec timeout;
    
    timeout.tv_sec = 0;
    timeout.tv_nsec = 1000*npctxt->flowExportDelay;
    while((nanosleep(&timeout, &timeout) == -1)
    	  && (errno == EINTR))
          ;*/ /* Do nothing */
	/* It seems that usleep has problems on some architectures */
    usleep(npctxt->flowExportDelay);
#else
    waitForNextEvent(npctxt->flowExportDelay);
#endif
  }

  if(npctxt->fileexportHandle != NULL) {
    u_int8_t magic = 0x7F;

    /* Write first magic number (for synchronization, error-checking), */
    /* then write length of the record. */

    fwrite(&magic,1,1,npctxt->fileexportHandle);
    fwrite(&bufferLength,sizeof(u_int32_t),1,npctxt->fileexportHandle);
    fwrite(buffer,bufferLength,1,npctxt->fileexportHandle);
    /* PENDING should we do the SHM write when doing this? */
  }
  
  if (npctxt->numCollectors == 0) {
    /* Write to mapi shared memory */
    ifp_write_shm(npctxt->mapi_ctxt, buffer, bufferLength);
  } else {
    /* Send flows to all collectors in round robin */
    if(npctxt->netFlowDest[npctxt->collectorId].isV6 == 0)
	rc = sendto(npctxt->netFlowOutSocket, buffer, bufferLength,
		    0, (struct sockaddr *)&npctxt->netFlowDest[npctxt->collectorId].u.v4Address,
		    sizeof(npctxt->netFlowDest[npctxt->collectorId].u.v4Address));
    else
      rc = sendto(npctxt->netFlowOutSocket, buffer, bufferLength,
		    0, (struct sockaddr *)&npctxt->netFlowDest[npctxt->collectorId].u.v6Address,
		  sizeof(npctxt->netFlowDest[npctxt->collectorId].u.v6Address));
    
    if(rc != bufferLength) {
      traceEvent(npctxt, TRACE_WARNING, "Error while exporting flows (%s)",
		 strerror(errno));
    }
    
    /* Switch to next collector */
    npctxt->collectorId = (npctxt->collectorId + 1) % npctxt->numCollectors; 
  }
}

/* ****************************************************** */

static void 
sendNetFlowV5(np_ctxt_t *npctxt, u_char lastFlow) 
{
  int len;
  NetFlow5Record *theV5Flow = &npctxt->v5Flow;

  if(theV5Flow->flowHeader.count == 0) return;

  if(npctxt->traceMode == 2)
    traceEvent(npctxt, TRACE_INFO, "Sending %d flows (NetFlowV5 format)",
	       ntohs(theV5Flow->flowHeader.count));

  len = (ntohs(theV5Flow->flowHeader.count)*sizeof(struct flow_ver5_rec)+sizeof(struct flow_ver5_hdr));

  if(npctxt->flowFd && (npctxt->textFormat == NULL)) {
#ifdef HAVE_ZLIB_H
    if(npctxt->compressFlows) {
      Byte outBuf[2000];
      uLongf outBufLen = sizeof(outBuf);

      if(compress(outBuf, &outBufLen, (const Bytef*)theV5Flow, len) == Z_OK) {
	fprintf(npctxt->flowFd, "%04d", (int)outBufLen);
	(void)fwrite((const  void*)outBuf, outBufLen, 1, npctxt->flowFd);
	if(npctxt->traceMode == 2)
	  traceEvent(npctxt, TRACE_INFO, "Compression %d->%d [%d %% size]",
		     len, outBufLen, (outBufLen*100)/len);

	sendNetFlow(npctxt, outBuf, outBufLen, lastFlow);
      } else {
	traceEvent(npctxt, TRACE_ERROR, "Unable to compress flow (len=%d)", len);
      }
    } else
#endif
      {
	fprintf(npctxt->flowFd, "%04d", len);
	(void)fwrite((const  void*)theV5Flow, len, 1, npctxt->flowFd);
      }
  }

  sendNetFlow(npctxt, (const void *)theV5Flow, len, lastFlow);
}

/* ****************************************************** */

static void 
initNetFlowV5Header(np_ctxt_t *npctxt) 
{
  long secs, usecs;
  NetFlow5Record *theV5Flow = &npctxt->v5Flow;

  memset(&theV5Flow->flowHeader, 0, sizeof(theV5Flow->flowHeader));

  theV5Flow->flowHeader.version        = htons(5);
  theV5Flow->flowHeader.sysUptime      = htonl(msTimeDiff(actTime, npctxt->initialSniffTime));
  secs  = actTime >> 32;
  usecs = (unsigned long) (actTime & 0xffffffff) / 4295;
  theV5Flow->flowHeader.unix_secs      = htonl(secs);
  theV5Flow->flowHeader.unix_nsecs     = htonl(usecs * 1000);
  theV5Flow->flowHeader.flow_sequence  = htonl(npctxt->flowSequence);
  theV5Flow->flowHeader.engine_type    = htons(engineType);
  theV5Flow->flowHeader.engine_id      = htons(engineId);
  theV5Flow->flowHeader.sampleRate     = htons(npctxt->sampleRate);
}

/* ****************************************************** */

static void 
initNetFlowV9Header(np_ctxt_t *npctxt) 
{
  V9FlowHeader *v9Header = &npctxt->v9Header;

  memset(v9Header, 0, sizeof(V9FlowHeader));
  v9Header->version        = htons(9);
  v9Header->sysUptime      = htonl(msTimeDiff(actTime, 
					      npctxt->initialSniffTime));
  v9Header->unix_secs      = htonl(time(NULL));
  v9Header->flow_sequence  = htonl(npctxt->flowSequence);
  v9Header->sourceId       = htonl(npctxt->observationDomainID);
}

/* ****************************************************** */

static void 
initNetFlowIPFIXHeader(np_ctxt_t *npctxt) 
{
  IPFIXFlowHeader *ipfixHeader = &npctxt->ipfixHeader;

  memset(ipfixHeader, 0, sizeof(IPFIXFlowHeader));
  ipfixHeader->version        = htons(0x0a);
  ipfixHeader->length         = 0; /* set at time of export */
  ipfixHeader->exportTime     = 0; /* set at time of export */
  ipfixHeader->flow_sequence  = htonl(npctxt->flowSequence-
				      (u_int32_t)npctxt->numFlows);
  ipfixHeader->sourceId       = htonl(npctxt->observationDomainID);
}

/* ****************************************************** */


static void 
sendNetFlowV9template(np_ctxt_t *npctxt) 
{
  V9Template templateDef;
  int templateBufBegin = 0, templateBufMax = NETFLOW_MAX_BUFFER_LEN;
  int numElements, bufLen;
  char templateBuffer[NETFLOW_MAX_BUFFER_LEN], buf[NETFLOW_MAX_BUFFER_LEN];

  flowPrintf(npctxt,npctxt->v9TemplateList, 
	     templateBuffer, &templateBufBegin, &templateBufMax,
	     &numElements, 1, NULL, 0, 0);

  initNetFlowV9Header(npctxt);
  npctxt->v9Header.count = htons(1);

  /* ********************** */

  templateDef.templateFlowset = 0;
  templateDef.fieldCount = htons(numElements);
  templateDef.flowsetLen = htons(8+templateBufBegin);
  templateDef.templateId = htons(npctxt->templateID);

  bufLen = 0;
  memcpy(&buf[bufLen], &npctxt->v9Header, sizeof(npctxt->v9Header));
  bufLen += sizeof npctxt->v9Header;
  memcpy(&buf[bufLen], &templateDef, sizeof(V9Template)); bufLen += sizeof(V9Template);
  memcpy(&buf[bufLen], templateBuffer, templateBufBegin); bufLen += templateBufBegin;

  sendNetFlow(npctxt, (const void *)buf, bufLen, 0);
}
/* ****************************************************** */


static void 
sendNetFlowIPFIXtemplate(np_ctxt_t *npctxt) 
{
  V9Template templateDef;
  int templateBufBegin = 0, templateBufMax = NETFLOW_MAX_BUFFER_LEN;
  int numElements, bufLen;
  char templateBuffer[NETFLOW_MAX_BUFFER_LEN], buf[NETFLOW_MAX_BUFFER_LEN];

  flowPrintf(npctxt,npctxt->v9TemplateList, 
	     templateBuffer, &templateBufBegin, &templateBufMax,
	     &numElements, 1, NULL, 0, 0);

  initNetFlowIPFIXHeader(npctxt);
  /*npctxt->ipfixHeader.count = htons(1); */

  /* ********************** */

  templateDef.templateFlowset = htons(2);
  templateDef.fieldCount = htons(numElements);
  templateDef.flowsetLen = htons(8+templateBufBegin);
  templateDef.templateId = htons(npctxt->templateID);

  bufLen = 0;
  npctxt->ipfixHeader.length = htons(sizeof(IPFIXFlowHeader) + sizeof(templateDef) + templateBufBegin);
  npctxt->ipfixHeader.exportTime = htonl(time(NULL));
  memcpy(&buf[bufLen], &npctxt->ipfixHeader, sizeof(npctxt->ipfixHeader));
  bufLen += sizeof npctxt->ipfixHeader;
  memcpy(&buf[bufLen], &templateDef, sizeof(V9Template)); 
  bufLen += sizeof(V9Template);
  memcpy(&buf[bufLen], templateBuffer, templateBufBegin); 
  bufLen += templateBufBegin;

  sendNetFlow(npctxt, (const void *)buf, bufLen, 0);
}

/* ****************************************************** */

#if 0
static void 
printHash(np_ctxt_t *npctxt) {
  u_int i;

  for(i = 0; i<npctxt->hashSize; i++) {
    if(npctxt->hash[i] != NULL)
      printf("theHash[%4d]\n", i);
  }
}
#endif

/* ****************************************************** */

static void 
initNflowHeader(np_ctxt_t *npctxt) {
  long secs, usecs;
  NflowV1Header *nFlowHeader = &npctxt->nFlowHeader;

  nFlowHeader->version        = htons(NFLOW_VERSION);
  nFlowHeader->sysUptime      = htonl(msTimeDiff(actTime, 
						 npctxt->initialSniffTime));
  secs  = actTime >> 32;
  usecs = (unsigned long) (actTime & 0xffffffff) / 4295;
  nFlowHeader->unix_secs      = htonl(secs);
  nFlowHeader->unix_nsecs     = htonl(usecs * 1000);
  nFlowHeader->flow_sequence  = htonl(npctxt->flowSequence);
  nFlowHeader->sourceId       = htons(engineType); /* CHECK */
  nFlowHeader->sampleRate     = htons(npctxt->sampleRate);
}

/* ****************************************************** */

/*#ifdef 0
static void 
dumpBuffer(char *buffer, int bufferLength) {
  int i;

  if(bufferLength > 512) bufferLength = 512;

  for(i=0; i<bufferLength; i++) {
    if(!(i % 8)) printf("\n");
    printf("%3d[%02x] ", i, buffer[i] & 0xFF );
  }

  printf("\n");
}
#endif */

/* ****************************************************** */

static void 
prepareNFlow(np_ctxt_t *npctxt, unsigned char *buffer,  
	     u_int32_t bufferLength) 
{
#ifdef HAVE_ZLIB_H
  uLongf compressedBufferLen;
  Byte compressedBuffer[NFLOW_SIZE_THRESHOLD];
#endif
  md5_state_t state;
  md5_byte_t digest[16];
  unsigned short digestLen;
  NflowV1Header *theNflowHeader = &npctxt->nFlowHeader;

  digestLen = strlen((char *)npctxt->nFlowKey); 
  if(digestLen > NFLOW_SUM_LEN) digestLen = NFLOW_SUM_LEN;
  memcpy(theNflowHeader->md5Sum, npctxt->nFlowKey, sizeof(npctxt->nFlowKey));

  if(digestLen < NFLOW_SUM_LEN)
    memset(&theNflowHeader->md5Sum[digestLen], ' ', NFLOW_SUM_LEN-digestLen); /* pad it with spaces */

  digestLen = bufferLength;
  memcpy(buffer, theNflowHeader, sizeof(NflowV1Header));

  md5_init(&state);
  md5_append(&state, (const md5_byte_t *)buffer, digestLen);
  md5_finish(&state, digest);

  memcpy(theNflowHeader->md5Sum, digest, NFLOW_SUM_LEN);
  memcpy(buffer, theNflowHeader, sizeof(NflowV1Header));

  //#ifdef 0
  //  dumpBuffer(buffer, bufferLength);
  //#endif

#ifdef HAVE_ZLIB_H
  compressedBufferLen = sizeof(compressedBuffer);
  if(compress(compressedBuffer, &compressedBufferLen,(const Bytef*)buffer, bufferLength) == Z_OK) {
    traceEvent(npctxt, TRACE_INFO, "Compressing: %d -> %d [%d %%]", bufferLength, compressedBufferLen,
	       (100*compressedBufferLen)/bufferLength);
    sendNetFlow(npctxt, compressedBuffer, compressedBufferLen, 0);
  } else
    traceEvent(npctxt, TRACE_ERROR, "compress() failed");
#else
  sendNetFlow(npctxt, buffer, bufferLength, 0);
#endif
}

/* ****************************************************** */

static void 
sendNetFlowV9(np_ctxt_t *npctxt, __attribute__((__unused__)) u_char lastFlow) 
{
  V9FlowSet flowSet;
  char flowBuffer[NETFLOW_MAX_BUFFER_LEN];
  int bufLen = 0;

  if(npctxt->templateSent == 0) {
    sendNetFlowV9template(npctxt);
    npctxt->templateSent = 1;
  }

  flowSet.templateId = htons(npctxt->templateID);
  flowSet.flowsetLen = htons(npctxt->bufferLen+4);

  memcpy(&flowBuffer[bufLen], &npctxt->v9Header, sizeof npctxt->v9Header);
  bufLen += sizeof(npctxt->v9Header);
  memcpy(&flowBuffer[bufLen], &flowSet, sizeof(flowSet)); 
  bufLen += sizeof(flowSet);
  memcpy(&flowBuffer[bufLen], npctxt->npBuffer, npctxt->bufferLen); 
  bufLen += npctxt->bufferLen;

  sendNetFlow(npctxt, (const void *)&flowBuffer, bufLen, 0);
  npctxt->bufferLen = 0;
}

/* ****************************************************** */

static void 
sendNetFlowIPFIX(np_ctxt_t *npctxt, __attribute__((__unused__)) u_char lastFlow) 
{
  V9FlowSet flowSet;
  char flowBuffer[NETFLOW_MAX_BUFFER_LEN];
  int bufLen = 0;

  if(npctxt->templateSent == 0) {
    sendNetFlowIPFIXtemplate(npctxt);
    npctxt->templateSent = 1;
  }

  flowSet.templateId = htons(npctxt->templateID);
  flowSet.flowsetLen = htons(npctxt->bufferLen+4);

  npctxt->ipfixHeader.length = htons(sizeof(IPFIXFlowHeader) + sizeof(flowSet) + npctxt->bufferLen);
  npctxt->ipfixHeader.exportTime = htonl(time(NULL));
  memcpy(&flowBuffer[bufLen], &npctxt->ipfixHeader, sizeof npctxt->ipfixHeader);
  bufLen += sizeof(npctxt->ipfixHeader);
  memcpy(&flowBuffer[bufLen], &flowSet, sizeof(flowSet)); 
  bufLen += sizeof(flowSet);
  memcpy(&flowBuffer[bufLen], npctxt->npBuffer, npctxt->bufferLen); 
  bufLen += npctxt->bufferLen;

  sendNetFlow(npctxt, (const void *)&flowBuffer, bufLen, 0);
  npctxt->bufferLen = 0;
}

/* ****************************************************** */

static void 
checkNetFlowExport(np_ctxt_t *npctxt, int forceExport) 
{
  int emitFlow = (npctxt->numFlows >= npctxt->minNumFlowsPerPacket);

  unsigned long long now = actTime;

  if(forceExport || emitFlow
     || (npctxt->numFlows && npctxt->lastExportTime
	 && (now > (npctxt->lastExportTime +  
		    ((unsigned long long) npctxt->sendTimeout << 32))))) {
    if (npctxt->numFlows > 0) {
      if(npctxt->netFlowVersion == 5) {
	initNetFlowV5Header(npctxt);
	npctxt->v5Flow.flowHeader.count = htons(npctxt->numFlows);
	sendNetFlowV5(npctxt, 0);
      } else if(npctxt->netFlowVersion == 9) {
	if (now  > (npctxt->lastTmpltExportTime + 
		    ((unsigned long long) npctxt->tmpltTimeout << 32)))
	  npctxt->templateSent = 0; /* Time to export templates again */
	if (npctxt->templateSent == 0)
	  npctxt->lastTmpltExportTime = now;
	initNetFlowV9Header(npctxt);
	npctxt->v9Header.count = htons(npctxt->numFlows);
	sendNetFlowV9(npctxt, 0);
      } else { /* Assume IPFIX 0x0a */
	if (now  > (npctxt->lastTmpltExportTime + 
		    ((unsigned long long) npctxt->tmpltTimeout << 32)))
	  npctxt->templateSent = 0; /* Time to export templates again */
	if (npctxt->templateSent == 0)
	  npctxt->lastTmpltExportTime = now;
	initNetFlowIPFIXHeader(npctxt);
	sendNetFlowIPFIX(npctxt, 0);
      }
    }
    npctxt->numFlows = 0, totExports++, npctxt->numExports++;
    npctxt->lastExportTime = now;
    npctxt->exportedFlowsSinceLastPkt = 0;
  }
}

/* ****************************************************** */

static void 
checkExportQueuedFlows(np_ctxt_t *npctxt, int forceExport) 
{
  if(npctxt->useNetFlow)
    checkNetFlowExport(npctxt, forceExport);
  else
    checknFlowExport(npctxt, forceExport);
}

/* ****************************************************** */

static int 
exportBucketToNetflowV5(np_ctxt_t *npctxt, HashBucket *myBucket, 
			int direction) 
{
  NetFlow5Record *theV5Flow = &npctxt->v5Flow;
  int numFlows = npctxt->numFlows;

  if(numFlows >= V5FLOWS_PER_PAK) {
    printf("BAD FLOW NUM\n");
    traceEvent(npctxt, TRACE_INFO, "Bad number of flows");
    return 0;
  }

  if(direction == 0 /* src -> dst */) {
    if(myBucket->pktSent == 0) return(0); /* Nothing to export */
    theV5Flow->flowRecord[numFlows].srcaddr   = htonl(myBucket->src.ipType.ipv4);
    theV5Flow->flowRecord[numFlows].dstaddr   = htonl(myBucket->dst.ipType.ipv4);
    theV5Flow->flowRecord[numFlows].dPkts     = htonl((u_int32_t)myBucket->pktSent);
    theV5Flow->flowRecord[numFlows].dOctets   = htonl(myBucket->bytesSent);
#ifdef DEBUG_TIMESTAMP
      traceEvent(npctxt, TRACE_INFO, "%s. %s=%d, %s=%u.%u, %s=%u.%u, %s=%u, %s=%u\n",
		 "exportBucketToNetflowV5",
		 "direction", direction,
		 "myBucket->firstSeenSent", 
		 (unsigned long) (myBucket->firstSeenSent >> 32),
		 (unsigned long) (((myBucket->firstSeenSent & 0xffffffff) 
				   * 1000) / 4295),
		 "myBucket->lastSeenSent", 
		 (unsigned long) (myBucket->lastSeenSent >> 32),
		 (unsigned long)(((myBucket->lastSeenSent & 0xffffffff)
				   * 1000) / 4295),
	       "First", 
	       msTimeDiff(myBucket->firstSeenSent, npctxt->initialSniffTime),
	       "Last",
	       msTimeDiff(myBucket->lastSeenSent, npctxt->initialSniffTime));
#endif
    theV5Flow->flowRecord[numFlows].First     = htonl(msTimeDiff(myBucket->firstSeenSent, npctxt->initialSniffTime));
    theV5Flow->flowRecord[numFlows].Last      = htonl(msTimeDiff(myBucket->lastSeenSent, npctxt->initialSniffTime));
    theV5Flow->flowRecord[numFlows].srcport   = htons(myBucket->sport);
    theV5Flow->flowRecord[numFlows].dstport   = htons(myBucket->dport);
    theV5Flow->flowRecord[numFlows].tos       = myBucket->src2dstTos;
    theV5Flow->flowRecord[numFlows].src_as    = htons(ip2AS(myBucket->src));
    theV5Flow->flowRecord[numFlows].dst_as    = htons(ip2AS(myBucket->dst));
    theV5Flow->flowRecord[numFlows].tcp_flags = myBucket->src2dstTcpFlags;
  } else {
    if(myBucket->pktRcvd == 0) return(0); /* Nothing to export */
    theV5Flow->flowRecord[numFlows].srcaddr   = htonl(myBucket->dst.ipType.ipv4);
    theV5Flow->flowRecord[numFlows].dstaddr   = htonl(myBucket->src.ipType.ipv4);
    theV5Flow->flowRecord[numFlows].dPkts     = htonl((u_int32_t)myBucket->pktRcvd);
    theV5Flow->flowRecord[numFlows].dOctets   = htonl(myBucket->bytesRcvd);
    theV5Flow->flowRecord[numFlows].First     = htonl(msTimeDiff(myBucket->firstSeenRcvd, npctxt->initialSniffTime));
    theV5Flow->flowRecord[numFlows].Last      = htonl(msTimeDiff(myBucket->lastSeenRcvd, npctxt->initialSniffTime));
    theV5Flow->flowRecord[numFlows].srcport   = htons(myBucket->dport);
    theV5Flow->flowRecord[numFlows].dstport   = htons(myBucket->sport);
    theV5Flow->flowRecord[numFlows].tos       = myBucket->dst2srcTos;
    theV5Flow->flowRecord[numFlows].src_as    = htons(ip2AS(myBucket->dst));
    theV5Flow->flowRecord[numFlows].dst_as    = htons(ip2AS(myBucket->src));
    theV5Flow->flowRecord[numFlows].tcp_flags = myBucket->dst2srcTcpFlags;
  }

  theV5Flow->flowRecord[numFlows].input     = htons(npctxt->ingress_interface);
  theV5Flow->flowRecord[numFlows].output    = htons(255 /* unknown device */);
  theV5Flow->flowRecord[numFlows].prot      = myBucket->proto;
  return(1);
}

/* ****************************************************** */

static int 
exportBucketToNetflowV9(np_ctxt_t *npctxt, HashBucket *myBucket, 
			int direction) 
{
  int flowBufBegin = npctxt->bufferLen, flowBufMax = NETFLOW_MAX_BUFFER_LEN;
  int numElements;

  if(direction == 0 /* src -> dst */) {
    if(myBucket->pktSent == 0) return(0); /* Nothing to export */
  } else {
    if(myBucket->pktRcvd == 0) return(0); /* Nothing to export */
  }

  flowPrintf(npctxt, npctxt->v9TemplateList, (char *)npctxt->npBuffer, &flowBufBegin, &flowBufMax,
	     &numElements, 0, myBucket, direction, 0);

  npctxt->bufferLen = flowBufBegin;
  return(1);
}

/* ****************************************************** */

static int 
exportBucketToNetflow(np_ctxt_t *npctxt, HashBucket *myBucket, int direction) 
{
  int rc = 0;
  mapi_offline_device_status_t offstat;

  if(npctxt->netFlowVersion == 5) {
    if(myBucket->src.ipVersion == 4)
      rc = exportBucketToNetflowV5(npctxt, myBucket, direction);
    else {
      static char msgPrinted = 0;

      if(!msgPrinted) {
 	traceEvent(npctxt, TRACE_INFO, "Unable to export IPv6 flow using NetFlowV5. Dropped.");
	msgPrinted = 1;
      }
    }
  } else
    rc = exportBucketToNetflowV9(npctxt, myBucket, direction);
  npctxt->exportedFlowsTotalCount = npctxt->exportedFlowsTotalCount + 1;
  npctxt->exportedFlowsSinceLastPkt = npctxt->exportedFlowsSinceLastPkt + 1;


  if(rc) {
    if(npctxt->traceMode == 2) printFlow(npctxt, myBucket, direction);
    if(npctxt->flowFd && npctxt->textFormat) 
      nprintf(npctxt->flowFd, (char *)npctxt->textFormat, myBucket, direction);
    
    npctxt->numFlows++, npctxt->totFlows++, npctxt->flowSequence++;
    offstat = ifp_get_offline_device_status (npctxt->mapi_ctxt);
    checkNetFlowExport(npctxt, offstat >= DEVICE_FINISHED);
  }

  return(rc);
}

/* ****************************************************** */

static void 
checknFlowExport(np_ctxt_t *npctxt, int forceExport) 
{
  int emitFlow = (npctxt->numFlows >= npctxt->minNumFlowsPerPacket);

  if(forceExport || emitFlow
     || (npctxt->numFlows && npctxt->lastExportTime
	 && (actTime > (npctxt->lastExportTime + 
			((unsigned long long) npctxt->sendTimeout >> 32))))) {
    npctxt->nFlowHeader.count = htons(npctxt->numFlows);
    prepareNFlow(npctxt, npctxt->npBuffer, npctxt->bufferLen);
    initNflowHeader(npctxt); 
    npctxt->bufferLen = sizeof(npctxt->nFlowHeader);
    memcpy(npctxt->npBuffer, &npctxt->nFlowHeader, npctxt->bufferLen);
    npctxt->numFlows = 0, totExports++, npctxt->numExports++;
  }
}

/* ****************************************************** */

static int 
exportBucketTonFlow(np_ctxt_t *npctxt, HashBucket *myBucket, int direction) 
{
  int numElements;
  char buf[512];
  int flowBufBegin = 0, flowBufMax = sizeof(buf);
  u_int16_t flowLen;

  if(direction == 0 /* src -> dst */) {
    if(myBucket->pktSent == 0) return(0); /* Nothing to export */
  } else {
    if(myBucket->pktRcvd == 0) return(0); /* Nothing to export */
  }

  flowPrintf(npctxt, npctxt->v9TemplateList, buf, &flowBufBegin, &flowBufMax,
	     &numElements, 0, myBucket, direction, 1);

  /* ********************** */

  flowLen = htons(flowBufBegin+2);
  memcpy(&npctxt->npBuffer[npctxt->bufferLen], &flowLen, 2); npctxt->bufferLen += 2;
  memcpy(&npctxt->npBuffer[npctxt->bufferLen], buf, flowBufBegin); 
  npctxt->bufferLen += flowBufBegin;

  if (npctxt->traceMode == 2) printFlow(npctxt, myBucket, direction);
  if (npctxt->flowFd && npctxt->textFormat) 
    nprintf(npctxt->flowFd,(char *) npctxt->textFormat, myBucket, direction);

  npctxt->numFlows++, npctxt->totFlows++, npctxt->flowSequence++;
  checknFlowExport(npctxt, 0);
  return(1);
}

/* ****************************************************** */
void 
npInitGlobals(void)
{
  ignoreAS = 0;
  engineType = 0, engineId = 0;
}


/* ****************************************************** */
/* This method returns 1 if param set, or 0 if not.       */
int get_param_int16(conf_category_entry_t *cat, const char *name, u_int16_t *val) {
  const char *optvalue = pc_get_param(cat, name);

  if(optvalue == NULL)
    return 0;

  *val = strtoul(optvalue, NULL, 10);
  return 1;
}
int get_param_int32(conf_category_entry_t *cat, const char *name, u_int32_t *val) {
  const char *optvalue = pc_get_param(cat, name);
  if(optvalue == NULL)
   return 0;

  *val = strtoul(optvalue, NULL, 10);
  return 1;
}


/* ****************************************************** */
np_ctxt_t *
npInitContext(void)
{
  struct timeval now;
  np_ctxt_t *npctxt = calloc(1, sizeof (np_ctxt_t));
  char* mapi_conf;
  char ac[80];
  int i;
  conf_category_t *conf;

  printf("npInitContext (l. %d): nInstances=%d\n", __LINE__, nInstances);
  if (!npctxt)
	  return NULL;
  npctxt->instanceNo = nInstances++;
  npctxt->netFlowVersion = 5; /* NetFlow v5 */
  npctxt->ignoreTcpUdpPorts = npctxt->ignoreIpAddresses = 0;
  npctxt->ignoreTos = 0;
  npctxt->numCollectors = 0;
  npctxt->hashSize = HASH_SIZE;
  npctxt->minFlowPkts = 1;
  npctxt->traceMode = 0;
  npctxt->traceToFile = 0;
  npctxt->flowExportDelay = 0;
  npctxt->idleTimeout = DUMP_TIMEOUT;
  npctxt->lifetimeTimeout = 8*DUMP_TIMEOUT;
  npctxt->sendTimeout = 5;
  npctxt->tmpltTimeout = 2*DUMP_TIMEOUT;
  npctxt->cacheTimeout = 12*DUMP_TIMEOUT;
  npctxt->useNetFlow = 0xFF;
  npctxt->computeFingerprint = 0;
  npctxt->netFlowOutSocket = -1;
  npctxt->fileexportName = NULL;
  npctxt->fileexportHandle = NULL;
  npctxt->tcpPayloadExport = 1; /* 1 captures all, 2 captures only SYN pkgs */
  npctxt->udpPayloadExport = 0;
  npctxt->icmpPayloadExport = 0; 
  npctxt->otherPayloadExport = 0;
  npctxt->compressFlows = 0;
  npctxt->textFormat = NULL;

  npctxt->maxExportQueueLatency = 1; /* Num of seconds to keep records. NEVER set to 0! */

  /* PENDING: conditionally set this, based on observed parameters. */
  npctxt->maxPayloadLen = 0;
  npctxt->bufferLen = 0;
  npctxt->numFlows = 0;
  npctxt->minNumFlowsPerPacket = 40;
  npctxt->maxNumFlowsPerPacket = 40; /* Loosely enforced */

  npctxt->lastExportTime = 0;
  npctxt->lastTmpltExportTime = 0;
  gettimeofday(&now, NULL);
  npctxt->initialSniffTime = ((unsigned long long)now.tv_sec << 32) 
	  + ((now.tv_usec * 4295) & 0xffffffff);
#ifdef DEBUG_TIMESTAMP
  printf("Initializing initialSniffTime to %Ld (%lu.%lu)\n",
	     npctxt->initialSniffTime,
	     (unsigned long) (npctxt->initialSniffTime >> 32),
	     (unsigned long) (((npctxt->initialSniffTime & 0xffffffff)
				   * 1000) / 4295)
);
#endif
  npctxt->scanCycle = 1;
  npctxt->sampleRate = 0;
  memset(npctxt->nFlowKey, ' ', sizeof npctxt->nFlowKey);
#ifdef IPV4_ONLY
  npctxt->useIpV6 = 0;
#else
  npctxt->useIpV6 = 1;
#endif
  npctxt->netFilter = NULL;
  npctxt->tmpDev = NULL;
  npctxt->npBuffer = NULL;
  npctxt->flowFd = NULL;
  npctxt->exportQueue = NULL;
  npctxt->exportQueueEnd = NULL;
  npctxt->exportBucketsLen = 0;
  npctxt->lastMaxBucketSearch = 5; /* Don't bother with values < 5 */

  npctxt->histPktSizeEnabled = 0;
  npctxt->histPktSizeBucket[0] =    50; /* See PKTSZ_HISTOGRAM_SLOTS */
  npctxt->histPktSizeBucket[1] =   100;
  npctxt->histPktSizeBucket[2] =   200;
  npctxt->histPktSizeBucket[3] =   750;
  npctxt->histPktSizeBucket[4] =  1300;
  npctxt->histPktSizeBucket[5] =  1400;
  npctxt->histPktSizeBucket[6] =  1450;
  npctxt->histPktSizeBucket[7] =  1500;
  npctxt->histPktSizeBucket[8] =0xFFFF;

  npctxt->histPktDistEnabled = 0;
  npctxt->histPktDistBucket[0] =    25; /* See PKTDIST_HISTOGRAM_SLOTS */
  npctxt->histPktDistBucket[1] =    50;
  npctxt->histPktDistBucket[2] =    75;
  npctxt->histPktDistBucket[3] =   100;
  npctxt->histPktDistBucket[4] =   200;
  npctxt->histPktDistBucket[5] =   300;
  npctxt->histPktDistBucket[6] =   400;
  npctxt->histPktDistBucket[7] =   500;
  npctxt->histPktDistBucket[8] =  1000;
  npctxt->histPktDistBucket[9] =0xFFFF;

  npctxt->bitrateCalcEnabled   = 0; //BITRATECALC_NONE;
  npctxt->pktDistLengthStddevs = 0;

  npctxt->serviceClassification = 0;
  npctxt->rtcp_enabled = 0;

  npctxt->ingress_interface = 0;
  npctxt->egress_interface = 0;
  npctxt->observationDomainID = DEFAULT_OBSERVATION_DOMAIN;

  npctxt->numObservedFlows = 0;

  npctxt->notsent_flows = 0;
  npctxt->notsent_pkts  = 0;
  npctxt->notsent_octets = 0;

  npctxt->exportedOctetTotalCount = 0;
  npctxt->exportedMessageTotalCount = 0;
  npctxt->exportedFlowsTotalCount = 0;
  npctxt->exportedFlowsSinceLastPkt = 0;

  npctxt->ignoredPacketTotalCount = 0;
  npctxt->ignoredOctetTotalCount  = 0;
  npctxt->initialPktsDropped = 0;

  srand(time(NULL));
  npctxt->templateID = 256+rand()%65000;

  /* Enterprise ID used for IPFIX custom fields
   * See http://www.iana.org/assignments/enterprise-numbers */
  npctxt->enterpriseId = 0;

  npctxt->statInterval  = STAT_INTERVAL;
  npctxt->statSkipCnt   = 0;
  npctxt->logfileOpened = 0;
  npctxt->loghandle     = NULL;

  mapi_conf = CONFDIR"/"CONF_FILE;
  if((conf = pc_load(mapi_conf)) != NULL) {    
    conf_category_entry_t *cat;
    cat = pc_get_category(conf, "ipfixflib");
    if(cat!=NULL) {
      /* These methods return 1 if options are successfully set. */
      get_param_int32(cat, "observationDomain", &npctxt->observationDomainID);
      get_param_int16(cat, "ingressInterface",  &npctxt->ingress_interface);
      get_param_int16(cat, "egressInterface", &npctxt->egress_interface);
      get_param_int32(cat, "enterpriseid", &npctxt->enterpriseId);
      get_param_int32(cat, "hashSize", &npctxt->hashSize);
      get_param_int16(cat, "scanCycle", &npctxt->scanCycle);
      get_param_int16(cat, "traceMode",  &npctxt->traceMode);
      get_param_int16(cat, "traceToFile",  &npctxt->traceToFile);
      get_param_int32(cat, "statInterval", &npctxt->statInterval);
      get_param_int16(cat, "idleTimeout", &npctxt->idleTimeout);
      get_param_int16(cat, "lifetimeTimeout", &npctxt->lifetimeTimeout);
      get_param_int16(cat, "cacheTimeout", &npctxt->cacheTimeout);
      get_param_int32(cat, "minFlowPkts",  &npctxt->minFlowPkts);
    } else {
      DEBUG_CMD(printf("Configuration file has no entry for `observationDomain' in `ipfixflib'. Using default ID %d\n", DEFAULT_OBSERVATION_DOMAIN));
    }
    pc_close(conf);
  }


  /* Attempt to get own IP address */
  if (gethostname(ac, sizeof(ac))==0) {
    struct hostent *phe = gethostbyname(ac);
    if (phe != NULL) {
      for (i = 0; phe->h_addr_list[i] != 0; ++i) {	
	if(phe->h_addrtype==AF_INET)
	  memcpy(&npctxt->exporterIpv4Address, phe->h_addr_list[i], sizeof(struct in_addr));
	else if(phe->h_addrtype==AF_INET6)
	  memcpy(&npctxt->exporterIpv6Address, phe->h_addr_list[i], sizeof(struct in6_addr));  
      }
    }
  }

  return npctxt;
}

/* ****************************************************** */

void 
npInitCounters(np_ctxt_t *npctxt)
{
  npctxt->totalPkts = 0, npctxt->totalBytes = 0;
  npctxt->totalTCPPkts = 0, npctxt->totalTCPBytes = 0;
  npctxt->totalUDPPkts = 0, npctxt->totalUDPBytes = 0;
  npctxt->totalICMPPkts = 0, npctxt->totalICMPBytes = 0;
  npctxt->currentPkts = 0, npctxt->currentBytes = 0;
  npctxt->currentTCPPkts = 0, npctxt->currentTCPBytes = 0;
  npctxt->currentUDPPkts = 0, npctxt->currentUDPBytes = 0;
  npctxt->currentICMPPkts = 0, npctxt->currentICMPBytes = 0;
  npctxt->lastSample = time(NULL);
  npctxt->totFlows = 0, npctxt->numExports = 0;
  npctxt->sumBucketSearch = 0;
}

/* ************************************ */

void 
shutdownInstance(np_ctxt_t *npctxt) 
{
  u_int i;

  npctxt->shutdownInProgress = 1;
  signalCondvar(&npctxt->exportQueueCondvar);
  pthread_join (npctxt->dequeueThread, NULL);
  pthread_join (npctxt->walkHashThread, NULL);
  for(i=0;i<npctxt->hashSize; i++) {
    walkHash(npctxt, 1);
  }

  traceEvent(npctxt, TRACE_INFO, "Flushing queued flows...\n");
  checkExportQueuedFlows(npctxt, 1);

  traceEvent(npctxt, TRACE_INFO, "Freeing memory...\n");

  close(npctxt->netFlowOutSocket);

  if(npctxt->fileexportHandle!=NULL) {
    fclose(npctxt->fileexportHandle);
  }
  if(npctxt->fileexportName!=NULL) {
    free(npctxt->fileexportName);
  }


  if (npctxt->usePcap)
    pcap_close(npctxt->pcapPtr);
  free(npctxt->hash);
  if(npctxt->tmpDev != NULL) free(npctxt->tmpDev);
  if(npctxt->npBuffer != NULL) free(npctxt->npBuffer);

  for(i=0; i<2; i++) {
    HashBucket *list;

    if(i == 0)
      list = npctxt->purgedBuckets;
    else
      list = npctxt->exportQueue;

    while(list != NULL) {
      HashBucket *nextEntry = list->next;

      if(list->src2dstPayload != NULL) free(list->src2dstPayload);
      if(list->dst2srcPayload != NULL) free(list->dst2srcPayload);
      free(list);
      npctxt->bucketsAllocated--;
      list = nextEntry;
    }
  }

  while(npctxt->fragmentsList != NULL) {
    IpV4Fragment *next = npctxt->fragmentsList->next;
    free(npctxt->fragmentsList);
    npctxt->fragmentsList = next;
  }

#ifdef DEBUG_EXPORT
  if(npctxt->bucketsAllocated > 0)
    traceEvent(npctxt, TRACE_INFO, "WARNING ===> bucketsAllocated: %d\n", npctxt->bucketsAllocated);
#endif

  traceEvent(npctxt, TRACE_INFO, "nProbe instance 0x%x terminated.\n", 
	     (int) npctxt);
#ifndef WIN32
  if(useSyslog)
    closelog();
  if (npctxt->loghandle)
    fclose(npctxt->loghandle);
#endif
  serviceClassificationFree(npctxt);
}

void shutdownNprobe() {
  static u_char once = 0;
  np_list_t *elt;

  if(once) return; else once = 1;

  traceEvent(NULL, TRACE_INFO, "nProbe is shutting down...\n");

  for (elt = np_contexts; elt != NULL; elt = elt->next)
    shutdownInstance((np_ctxt_t *)elt->data);
}


/* ******************************************* */

static int 
openDevice(np_ctxt_t *npctxt, char ebuf[], int printErrors) 
{
  if(npctxt->tmpDev == NULL) {
#ifdef WIN32
    npctxt->tmpDev = printAvailableInterfaces(0);
#else
    npctxt->tmpDev = strdup(pcap_lookupdev(ebuf));
#endif
    if(npctxt->tmpDev == NULL) {
      if(printErrors)
	traceEvent(npctxt, TRACE_ERROR,
		   "Unable to locate default interface (%s)\n", ebuf);
      return(-1);
    }
  }

  npctxt->usePcap = 1;
  npctxt->pcapPtr = pcap_open_live(npctxt->tmpDev, DEFAULT_SNAPLEN,
				   1 /* promiscous */, 100 /* ms */, ebuf);
  
  if(npctxt->pcapPtr == NULL)  {
    if(printErrors)
      traceEvent(npctxt, TRACE_ERROR, "Unable to open interface %s.\n", npctxt->tmpDev);
    
#ifndef WIN32
    if((getuid () && geteuid ()) || setuid (0)) {
      if(printErrors) {
	traceEvent(npctxt, TRACE_ERROR,
		   "ERROR: nProbe opens the network interface "
		   "in promiscuous mode, ");
	traceEvent(npctxt, TRACE_ERROR, "ERROR: so it needs root permission "
		   "to run. Quitting...");
      }
    }
#endif
    return(-1);
  }

  /* ************************ */

  if(npctxt->netFilter != NULL) {
    struct bpf_program fcode;
    struct in_addr netmask;

    netmask.s_addr = htonl(0xFFFFFF00);

    if((pcap_compile(npctxt->pcapPtr, &fcode, npctxt->netFilter, 1, netmask.s_addr) < 0)
       || (pcap_setfilter(npctxt->pcapPtr, &fcode) < 0)) {
      if(printErrors)
	traceEvent(npctxt, TRACE_ERROR,
		   "Unable to set filter %s. Filter ignored.\n", npctxt->netFilter);
      /* return(-1); */
    } else {
      if(printErrors)
	traceEvent(npctxt, TRACE_INFO, "Packet capture filter set to \"%s\"",
		   npctxt->netFilter);
    }

    free(npctxt->netFilter);
    npctxt->netFilter = NULL;
  }

  return(0);
}

/* ****************************************************** */

void restoreInterface(np_ctxt_t *npctxt, char ebuf[]) {
  int rc = -1;
  
  traceEvent(npctxt, TRACE_INFO,
	     "Error while capturing packets: %s",
	     pcap_geterr(npctxt->pcapPtr));
  traceEvent(npctxt, TRACE_INFO, "Waiting until the interface comes back...");
  
  while(rc == -1) {
    sleep(1);
    rc = openDevice(npctxt, ebuf, 0);
    }
  traceEvent(npctxt, TRACE_INFO, "The interface is now awailable again.");
}

/* ******************************** */

#ifdef WIN32
char* printAvailableInterfaces(int index) {
  char ebuf[PCAP_ERRBUF_SIZE];
  char *tmpDev = pcap_lookupdev(ebuf), *ifName;
  int ifIdx=0, defaultIdx = -1, numInterfaces = 0;
  u_int i;
  char intNames[32][256];

  if(tmpDev == NULL) {
    traceEvent(npctxt, TRACE_INFO, "Unable to locate default interface (%s)", ebuf);
    exit(-1);
  }

  ifName = tmpDev;

  if(index == -1) printf("Available interfaces:\n");

  if(!isWinNT()) {
    for(i=0;; i++) {
      if(tmpDev[i] == 0) {
	if(ifName[0] == '\0')
	  break;
	else {
	  if(index == -1) { numInterfaces++; printf("\t[index=%d] '%s'\n", ifIdx, ifName); }

	  if(ifIdx < 32) {
	    strcpy(intNames[ifIdx], ifName);
	    if(defaultIdx == -1) {
	      if(strncmp(intNames[ifIdx], "PPP", 3) /* Avoid to use the PPP interface */
		 && strncmp(intNames[ifIdx], "ICSHARE", 6)) { /* Avoid to use the internet sharing interface */
		defaultIdx = ifIdx;
	      }
	    }
	  }

	  ifIdx++;
	  ifName = &tmpDev[i+1];
	}
      }
    }

    tmpDev = intNames[defaultIdx];
  } else {
    /* WinNT/2K */
    static char tmpString[128];
    int i, j,ifDescrPos = 0;
    unsigned short *ifName; /* UNICODE */
    char *ifDescr;

    ifName = tmpDev;

    while(*(ifName+ifDescrPos) || *(ifName+ifDescrPos-1))
      ifDescrPos++;
    ifDescrPos++;	/* Step over the extra '\0' */
    ifDescr = (char*)(ifName + ifDescrPos); /* cast *after* addition */

    while(tmpDev[0] != '\0') {
      for(j=0, i=0; !((tmpDev[i] == 0) && (tmpDev[i+1] == 0)); i++) {
	if(tmpDev[i] != 0)
	  tmpString[j++] = tmpDev[i];
      }

      tmpString[j++] = 0;
      if(index == -1) {
	printf("\t[index=%d] '%s'\n", ifIdx, ifDescr);
	ifDescr += strlen(ifDescr)+1;
	numInterfaces++;
      }

      tmpDev = &tmpDev[i+3];
      strcpy(intNames[ifIdx++], tmpString);
      defaultIdx = 0;
    }
    
    if(defaultIdx != -1)
      tmpDev = intNames[defaultIdx]; /* Default */
  }

  if(index == -1) {
    if(numInterfaces == 0) {
      traceEvent(npctxt, TRACE_WARNING, "WARNING: no interfaces available! This application cannot");
      traceEvent(npctxt, TRACE_WARNING, "         work make sure that winpcap is installed properly");
      traceEvent(npctxt, TRACE_WARNING, "         and that you have network interfaces installed.");
    }
    return(NULL);
  } else if((index < 0) || (index > ifIdx)) {
    traceEvent(npctxt, TRACE_ERROR, "Index=%d out of range\n", index);
    exit(-1);
  } else
    return(intNames[index]);
}
#endif /* WIN32 */

