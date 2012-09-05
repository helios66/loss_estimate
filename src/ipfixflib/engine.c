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

#ifdef __KERNEL__
#include "sniffer_mod.h"
#include "nprobe_mod.h"
#include "mod_typedefs.h"
#include "engine.h"
#else /* __KERNEL__ */
#include "nprobe.h"
#endif /* __KERNEL__ */

#include "npctxt.h"
#include "mpegts.h"
/* ****************************** */

u_char ignoreAS;
#ifndef WIN32
int useSyslog = 0;
#endif
int traceLevel = 5;
unsigned long long actTime;
u_short engineType, engineId;

/* Extern */
extern pthread_mutex_t purgedBucketsMutex, hashMutex[MAX_HASH_MUTEXES];

static HashBucket *cacheFlow(np_ctxt_t *npctxt, HashBucket *bkt, time_t time);
static int cmpIpAddress(IpAddress src, IpAddress dst);

typedef enum {sip_invite, sip_ok, sip_progress, sip_giveup, sip_other} sip_msg_type;

#ifndef MIN
#define MIN(a,b) ((a)>(b)?(b):(a))
#endif

#define DEBUG_JK

/* ****************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ****************************** */

char* _intoa(IpAddress addr, char* buf, u_short bufLen) {
  if(addr.ipVersion == 4)
    return(_intoaV4(addr.ipType.ipv4, buf, bufLen));
  else
    return((char*)inet_ntop(AF_INET6, &addr.ipType.ipv6, buf, bufLen));
}

/* ****************************************************** */

char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if (numBits < 1048576) {
    snprintf(buf, 32, "%.0f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.0f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
	snprintf(buf, 32, "%.0f G%c", tmpMBits, unit);
      } else {
	snprintf(buf, 32, "%.0f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

/* ******************************************************** */

/*
  Fingerprint code courtesy of ettercap
  http://ettercap.sourceforge.net
*/
u_char ttlPredictor(u_char x) {		/* coded by awgn <awgn@antifork.org> */
					/* round the TTL to the nearest power of 2 (ceiling) */
  register u_char i = x;
  register u_char j = 1;
  register u_char c = 0;

  do {
    c += i & 1;
    j <<= 1;
  } while(i >>= 1);

  if(c == 1)
    return(x);
  else
    return(j ? j : 0xff);
}

/* ******************************************************** */

char* proto2name(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  case 2:            return("IGMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

/* ****************************************************** */

void setPayload(np_ctxt_t *npctxt, HashBucket *bkt, u_char *payload,
		int payloadLen,  int direction) {

  if(payloadLen > 0) {
    int diff;

    if(direction == 0) {
      if(bkt->src2dstPayload == NULL)
	bkt->src2dstPayload = (u_char*)malloc(sizeof(char)*(npctxt->maxPayloadLen+1));

      diff = npctxt->maxPayloadLen-bkt->src2dstPayloadLen;

      if(diff > 0) {
	if(diff > payloadLen) diff = payloadLen;
	memcpy(&bkt->src2dstPayload[bkt->src2dstPayloadLen], payload, diff);
	bkt->src2dstPayloadLen += diff;
      }
    } else {
      if(bkt->dst2srcPayload == NULL)
	bkt->dst2srcPayload = (u_char*)malloc(sizeof(char)*(npctxt->maxPayloadLen+1));

      diff = npctxt->maxPayloadLen-bkt->dst2srcPayloadLen;

      if(diff > 0) {
	if(diff > payloadLen) diff = payloadLen;
	memcpy(&bkt->dst2srcPayload[bkt->dst2srcPayloadLen], payload, diff);
	bkt->dst2srcPayloadLen += diff;
      }
    }
  }
}

/* ************************************************* */

void updateApplLatency(u_short proto, HashBucket *bkt,
		       int direction, unsigned long long stamp,
		       u_int8_t icmpType) {

  if(!applLatencyComputed(bkt)) {
    /*
      src ---------> dst -+
      | Application
      | Latency
      <--------      -+

      NOTE:
      1. Application latency is calculated as the time passed since the first
      packet sent the first packet on the opposite direction is received.
      2. Application latency is calculated only on the first packet

    */

    if(direction  == 0) {
      /* src->dst */
      if(bkt->src2dstApplLatency == 0)
	bkt->src2dstApplLatency = stamp;

      if(bkt->dst2srcApplLatency != 0) {
	bkt->dst2srcApplLatency  = bkt->src2dstApplLatency - bkt->dst2srcApplLatency;
	bkt->src2dstApplLatency = 0;
	NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->flags));
      }
    } else {
      /* dst -> src */
      if(bkt->dst2srcApplLatency == 0)
	bkt->dst2srcApplLatency = stamp;

      if(bkt->src2dstApplLatency != 0) {
	bkt->src2dstApplLatency  = bkt->dst2srcApplLatency - bkt->src2dstApplLatency;
	bkt->dst2srcApplLatency = 0;
	NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->flags));
      }
    }

#ifdef DEBUG_APPL_LATENCY
    if(applLatencyComputed(bkt)) {
      char buf[32], buf1[32];

      if(bkt->src2dstApplLatency)
	      printf("[Appl: %.2f ms (%s->%s)]", (float)(bkt->src2dstApplLatency / 1000),
	       _intoa(bkt->src, buf, sizeof(buf)), _intoa(bkt->dst, buf1, sizeof(buf1)));
      else
	      printf("[Appl: %.2f ms (%s->%s)]", (float)(bkt->dst2srcApplLatency / 1000)
		     _intoa(bkt->dst, buf, sizeof(buf)), _intoa(bkt->src, buf1, sizeof(buf1)));
    }
#endif
  }

  if(proto == IPPROTO_ICMP) {
    if(direction == 0)
      NPROBE_FD_SET(icmpType, &(bkt->src2dstIcmpFlags));
    else
      NPROBE_FD_SET(icmpType, &(bkt->dst2srcIcmpFlags));
  }
}


/* ****************************************************** */

void updateTcpFlags(HashBucket *bkt,
		    int direction,
		    unsigned long long stamp,
		    u_int8_t flags,
		    u_char *fingerprint,
		    u_char tos) {
  if(direction  == 0)
    bkt->src2dstTos |= tos;
  else
    bkt->dst2srcTos |= tos;

  return; /* FIX */

  if(!nwLatencyComputed(bkt)) {
    if(flags == TH_SYN) {
      bkt->nwLatency = stamp;
    } else if(flags == TH_ACK) {
      if(bkt->nwLatency == 0) {
	/* We missed the SYN flag */
	NPROBE_FD_SET(FLAG_NW_LATENCY_COMPUTED,   &(bkt->flags));
	NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->flags)); /* We cannot calculate it as we have
								     missed the 3-way handshake */
	return;
      }

      if(((direction  == 0)    && (bkt->src2dstTcpFlags != TH_SYN))
	 || ((direction  == 1) && (bkt->dst2srcTcpFlags != TH_SYN)))
	return; /* Wrong flags */

      if(stamp >= bkt->nwLatency) {
	bkt->nwLatency = stamp - bkt->nwLatency;

	bkt->nwLatency /= 2;
      } else
	bkt->nwLatency = 0;

#ifdef DEBUG_APPL_LATENCY
      printf("[Net: %.1f ms]",
	     (float)(bkt->nwLatency / 4294967));
#endif

      NPROBE_FD_SET(FLAG_NW_LATENCY_COMPUTED, &(bkt->flags));
      updateApplLatency(IPPROTO_TCP, bkt, direction, stamp, 0);
    }
  } else {
    /* Nw latency computed */
    if(!applLatencyComputed(bkt)) {
      /*
	src ---------> dst -+
	| Application
	| Latency
	<--------      -+

	NOTE:
	1. Application latency is calculated as the time passed since the first
	packet sent after the 3-way handshake until the first packet on
	the opposite direction is received.
	2. Application latency is calculated only on the first packet
      */

      updateApplLatency(IPPROTO_TCP, bkt, direction, stamp, 0);
    }
  }

  if(fingerprint != NULL) {
    if((direction == 0) && (bkt->src2dstFingerprint[0] == '\0'))
      memcpy(bkt->src2dstFingerprint, fingerprint, FINGERPRINT_LEN);
    else if((direction == 1) && (bkt->dst2srcFingerprint[0] == '\0'))
      memcpy(bkt->dst2srcFingerprint, fingerprint, FINGERPRINT_LEN);
  }
}


static int _min(int a, int b) {
  if(a>b) return b;
  return a;
}
static int _max(int a, int b) {
  if(a>b) return a;
  return b;
}

#define MAX_UINT32 0xFFFFFFFFul

/*
 * Update bucket to add a histogram reference to the given packet size.
 * Only the bar of the histogram corresponding to the given bucket will
 * be updated. Histogram bars are number of packets.
 *
 * Also sets max/min size of packets that have been observed.
 *
 */
static void updatePacketSizeStats(np_ctxt_t *npctxt, HashBucket *bkt, u_int len, u_int direction) {

  if(npctxt->histPktSizeEnabled != 0) {
    int i, bar_num=PKTSZ_HISTOGRAM_SLOTS-1;

    for(i=0; i<PKTSZ_HISTOGRAM_SLOTS; i++) {
      if(len <= npctxt->histPktSizeBucket[i]) {
	bar_num = i;
	break;
      }
    }
    if(direction==0)
      bkt->src2dstPktSizeHistogram[bar_num]++;
    else
      bkt->dst2srcPktSizeHistogram[bar_num]++;
  }
}

/* Returns number of microseconds that have passed */
static u_int32_t getUSDistance(unsigned long long new, unsigned long long old) {
  unsigned long long d = new-old;
  unsigned long uspassed = (float)(d / 4294);
  return uspassed;
}


/*
 * Do bitrate calculation for a packet.
 *
 * Bitrates can be calculated in intervals such as max/min bitrate over 1
 * second, over 100ms etc.
 *
 * Bitrate calculation is performed by splitting up the time period into 10
 * slots. All traffic during the slots are added to one of the slots. When
 * 1/10th of the bitrate-calculation's time is elapsed, all traffic will
 * be added to the next slot, and so on.
 *
 * 'slotTime' is the number of microseconds that each slot consists of.
 *     If calculating bitrate for a 1sec period, this will be 100.000 (.1sec).
 * 'force' is set to TRUE if we are instructed to calculate the bitrate (even
 *     when the total duration of the bitrate calculation hasn't run). The
 *     purpose of this is to always calculate bitrate before a flow record is
 *     exported.
 */
static void calculateBitrate(u_int32_t slotTime, u_int64_t stamp, u_int64_t *lastupdate, 
			     u_int32_t *rate_best_max, u_int32_t *rate_best_min,
			     u_int32_t *averager, u_int16_t *avgpos, u_int len,
			     u_int force) {
  u_int32_t i;
  u_int32_t numSlotsAdvance = getUSDistance(stamp,*lastupdate)/slotTime;

  // 'mult' is the number we must multiply the bytes/time_period with to get
  // a meaningful bytes/sec value.
  u_int32_t mult = 100000/slotTime;
  
  // Should we begin adding bytes to the next slot instead? If so, sum up the
  // bytes of all slots first, and check if this is a minimum/max.
  if(numSlotsAdvance > 0 || force) {
    u_int32_t sum = 0;
    for(i=0; i<BITRATE_AVERAGER_SLOTS; i++) {
      // If averager[i] is MAX_UINT32, this is an _uninitialized_ slot.
      // We don't want to continue calculating if we haven't run the 
      // total duration of the bitrate calculation yet.
      if(averager[i]==MAX_UINT32) {

	// In case of no-force, then break if a MAX_UINT32 is found.
	// This is because we are observing the beginning of a flow
	if(!force)
	  sum = MAX_UINT32;
	break;	
      }

      sum += averager[i];
    }
    
    // 'sum' is now the value BYTES/TIME_PERIOD. The bitrate calculation 
    // duration may be 1sec, in case BYTES/TIME_PERIOD is OK. If time 
    // period is 100MS, then we need to multiply by 10 to get Bytes/sec.
    if(sum != MAX_UINT32) {
      sum *= mult;
      if(sum < *rate_best_min)
	*rate_best_min = sum;
      if(sum > *rate_best_max)
	*rate_best_max = sum;
    }

    // do we need this?
    if(force)
      return;

    *lastupdate = stamp;
  }

  if(numSlotsAdvance >= BITRATE_AVERAGER_SLOTS) {
    // More time than in the entire averager-block has passed. Invalidate all.
    memset(averager, '\0', sizeof(u_int32_t)*BITRATE_AVERAGER_SLOTS);
    *rate_best_min = 0; // it's definitively a minimum
    *avgpos = 0;
  }
  else if(numSlotsAdvance > 0) {

    while(numSlotsAdvance > 0) {
      (*avgpos)++;
      if(*avgpos >= BITRATE_AVERAGER_SLOTS)
	*avgpos = 0;

      averager[*avgpos] = 0;
      numSlotsAdvance--;
    }    

    // Advance a given number of slots
    //memmove(averager,averager + numSlotsAdvance, sizeof(u_int32_t)*(BITRATE_AVERAGER_SLOTS-numSlotsAdvance));
    //memset(averager + (BITRATE_AVERAGER_SLOTS-numSlotsAdvance), '\0', numSlotsAdvance*sizeof(u_int32_t));
  }
  averager[*avgpos] += len;
} 



static void updateBitrateCalculation(np_ctxt_t *npctxt, HashBucket *bkt, u_int len, 
				     unsigned long long stamp, u_int direction, u_int force) {
  int i, b;
  // Calculate average bitrate of a period of time
  // This is done by continuously updating the bkt->bitrateAverager1sec array
  // and summing this at the end of each time slot (which is .1 secs)
  //
  // Note that the 10sec and 100sec intervals are only calculated correctly as a lower
  // bound. As a upper bound, they are "capped" on very fast network adapters.
  // (this is to avoid using 32bit data types)

  for(i=0; i<BITRATE_COUNT; i++) {
    if((npctxt->bitrateCalcEnabled & (1<<i)) != 0) {
      u_int32_t divnum = 100000;
      for(b=0; b<i; b++)
	divnum = divnum/10;

      if(direction==0)
	calculateBitrate(divnum, stamp, &bkt->src2dstBitrateLastUpdate[i],
			 &bkt->src2dstRateMax[i], &bkt->src2dstRateMin[i],
			 bkt->src2dstBitrateAverager[i],&bkt->src2dstBitrateAveragerPos[i],
			 len,force);
      else
	calculateBitrate(divnum, stamp, &bkt->dst2srcBitrateLastUpdate[i],
			 &bkt->dst2srcRateMax[i], &bkt->dst2srcRateMin[i],
			 bkt->dst2srcBitrateAverager[i],&bkt->dst2srcBitrateAveragerPos[i],
			 len,force);
    }
  }
}

static double
rtp_get_timeunit(int payload_type)
{
  static int samples_0[] = {
    8000 
  };
  static int samples_3[] = { 
    8000, 			/* 3 */
    8000, 			/* 4 */
    8000,			/* 5 */
    16000,			/* 6 */
    8000,			/* 7 */
    8000,			/* 8 */
    8000,			/* 9 */
    44100,			/* 10 */
    44100,			/* 11 */
    8000,			/* 12 */
    8000,			/* 13 */
    90000,			/* 14 */
    8000,			/* 15 */
    11025,			/* 16 */
    22050,			/* 17 */
    8000,			/* 18 */
  };
  static int samples_25[] = { 
    90000,			/* 25 */
    90000,			/* 26 */
  };
  static int samples_28[] = { 
    90000,			/* 28 */
  };
  static int samples_31[] = { 
    90000,			/* 31 */
    90000,			/* 32 */
    90000,			/* 33 */
    90000,			/* 34 */
  };
 
  int samples;

  if (payload_type == 0)
    samples = samples_0[payload_type];
  else if (payload_type >= 3 && payload_type <=  18)
    samples = samples_3[payload_type - 3];
  else if (payload_type >= 25 && payload_type <= 26)
    samples = samples_25[payload_type - 25];
  else if (payload_type == 28)
    samples = samples_28[payload_type - 28];
  else if (payload_type >= 31 && payload_type <= 34)
    samples = samples_31[payload_type - 31];
  else
    samples = 8000;

  return 1. / samples;
}

/*
 * Read RTP parameters
 * Make the assumption that this is a client connecting to a RTP server,
 * thus the destination port will be distinguishable.
 */
/* 
   JK: RTP timestamp resolution is media dependent. Typically, it is the sampling period of the 
   originating application. 

   Here is the header structure:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           timestamp                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           synchronization source (SSRC) identifier            |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |            contributing source (CSRC) identifiers             |
   |                             ....                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   RTCP sender report has NTP timestamp and a corresponding RTP timestamp.

 */
static void rtp_parse(u_int8_t *payload, u_int16_t payloadLen, int direction,
		      unsigned long long stamp, struct hashBucket *bkt) {
  struct _rtp_packet  *rtp = (struct _rtp_packet *)payload;
  u_int32_t mtime;
  u_int16_t seq, n_seq;
  rtp_stat_t *rtpstat;
  u_int32_t *rtp_seqnum;
  u_int32_t *rtp_oo_seq;
  
  if(payloadLen <  (sizeof(struct _rtcp_packet) + sizeof(struct _rtcp_rb)) ||
     rtp->v != 2 || bkt->proto != 17) {
    return; 			/* Not RTP */
  }

  seq = ntohs(rtp->seqnum);

  /* Media time */
  mtime = ntohl(rtp->ts);
  if (direction == 0) {
    rtpstat    = bkt->rtp_a_stat;
    /* We use the same sequence number fields as for TCP */
    rtp_seqnum = &bkt->src2dst_last_sequence_number;
    rtp_oo_seq = &bkt->src2dst_num_packets_out_of_sequence;
  } else {
    rtpstat    = bkt->rtp_b_stat;
    rtp_seqnum = &bkt->dst2src_last_sequence_number;
    rtp_oo_seq = &bkt->dst2src_num_packets_out_of_sequence;
  }
  rtpstat = (direction == 0) ? bkt->rtp_a_stat : bkt->rtp_b_stat;
  if (rtpstat->rtp_initialized == 0) {
    rtpstat->rtp_initialized = 1;
  } else {
    double mtr_incr_s = (mtime - rtpstat->rtp_timestamp) * rtp_get_timeunit(rtp->pt);
    double mtm_incr_s = (stamp - rtpstat->mapi_timestamp) / 4294967296.;
    double jitter = abs(mtm_incr_s - mtr_incr_s);
    double est_jitter;
    double average, stddev;

    n_seq = (*rtp_seqnum >= 65535) ? 0 : *rtp_seqnum + 1;
    if (seq == n_seq) {
      if (rtpstat->rtp_initialized == 1) {
	est_jitter = jitter;
	rtpstat->rtp_initialized = 2;
      } else {
	est_jitter = rtpstat->est_jitter + (jitter - rtpstat->est_jitter) / 16.;
      }
      rtpstat->njitter++;
      rtpstat->sum_jitter += jitter;
      rtpstat->sqsum_jitter += jitter*jitter;
      if (jitter < rtpstat->min_jitter) rtpstat->min_jitter = jitter;
      if (jitter > rtpstat->max_jitter) rtpstat->max_jitter = jitter;
      average = rtpstat->sum_jitter/rtpstat->njitter;
      stddev = sqrt((rtpstat->sqsum_jitter - average*average) / rtpstat->njitter);

      rtpstat->est_jitter = est_jitter;
      rtpstat->rtp_initialized = 2;
    } else {
      /* Lost or duplicated packet(s) */
      u_int16_t seqgap = (u_int16_t)seq - (u_int16_t)(*rtp_seqnum);
      if (seqgap <= 32767) {
	; 			/* Lost packets */
      } else {
	(*rtp_oo_seq)++;	/* Out of order / duplicated */
      }
    }
  }

  *rtp_seqnum = seq;
  rtpstat->rtp_timestamp = mtime;
  rtpstat->mapi_timestamp = stamp;
}

static void read_rtp_parameters(u_int8_t *payload, u_int16_t payloadLen, 
				struct hashBucket *bkt) {
  struct _rtp_packet  *rtp = (struct _rtp_packet *)payload;
  struct _rtcp_packet *rtcp = (struct _rtcp_packet *)payload;
  struct _rtcp_rb     *rb;

  /* Detect RTP through 4,25 header bytes. Rely on that RTP is using UDP (usually OK) */
  if(payloadLen >=  (sizeof(struct _rtcp_packet) + sizeof(struct _rtcp_rb)) &&
     rtp->v == 2 && bkt->proto == 17) {
    if (rtcp->pt >  RTP_IANA_MAX_ASSIGNED_PT + 5 &&
	(rtcp->pt < RTP_IANA_MIN_DYNAMIC_PT ||
	 rtcp->pt > RTP_IANA_MAX_DYNAMIC_PT)) {
      bkt->rtp_sniff_res = NOT_RTP;
      if (rtcp->pt == RTCP_RECEIVER_REPORT &&
	  ntohs(rtcp->len) == (2 + rtcp->rc*sizeof(struct _rtcp_rb)/4 - 1)) {
	/* RTCP */
	rb = (struct _rtcp_rb *)(payload + sizeof(struct _rtcp_packet));
	if(rtcp->rc >= 1) {
	  bkt->rtcp_jitter   = ntohl(rb->jitter);
	  bkt->rtcp_lostfrac = rb->lost_fract;
	  bkt->rtcp_lostpkts = ntohl(rb->lost_pkts);
	  bkt->rtcp_cycles   = ntohl(rb->max_seq)>>16;
	}
      }
    } else if (bkt->rtp_sniff_res == RTP_SNIFF_NOT_STARTED) {
      bkt->rtp_sync_source = rtp->ssrc;
      bkt->rtp_last_sequence_number = rtp->seqnum;
    } else if (bkt->rtp_sniff_res == MAYBE_RTP){
      /* Sender ID must be the same */
      if (rtp->ssrc != bkt->rtp_sync_source) {
	/* There may be sequence number discrepancies, but not too much */
	int32_t seq_gap = rtp->seqnum - bkt->rtp_last_sequence_number;
	bkt->rtp_sniff_res = NOT_RTP;
	bkt->rtp_sequence_badness += abs(seq_gap - 1);
      }
    } else {
      ;				/* Not RTP */
    }
  }
  return;
}

static inline u_int32_t
getHashIdx(np_ctxt_t *npctxt, 
	   IpAddress src, u_short sport, IpAddress dst, u_short dport)
{
  u_int32_t idx;
  u_int32_t srcHost, dstHost;

  if(src.ipVersion == 4) {
    srcHost = src.ipType.ipv4, dstHost = dst.ipType.ipv4;
  } else {
    srcHost = src.ipType.ipv6.s6_addr32[0]+src.ipType.ipv6.s6_addr32[1]
      +src.ipType.ipv6.s6_addr32[2]+src.ipType.ipv6.s6_addr32[3];
    dstHost = dst.ipType.ipv6.s6_addr32[0]+dst.ipType.ipv6.s6_addr32[1]
      +dst.ipType.ipv6.s6_addr32[2]+dst.ipType.ipv6.s6_addr32[3];
  }

#if 0
  idx = (u_int)((srcHost & 0xffff) ^ ((srcHost >> 15) & 0xffff) ^
		((dstHost << 1) & 0xffff) ^ ((dstHost >> 16 ) & 0xffff) ^
		(dport << 1) ^ (sport));
#else
  idx = srcHost+dstHost+sport+dport;
#endif

  idx %= npctxt->hashSize;

  return idx;
}


static void
sip_media_flow_add(np_ctxt_t *npctxt, HashBucket *bkt, IpAddress b_addr, u_short b_port)
{
  u_int32_t idx;
  HashBucket *obkt, tmpbkt, *cacheBucket;
  IpAddress a_addr = bkt->sip_rtp_a_addr;
  u_short   a_port = bkt->sip_rtp_a_port;
  u_int16_t serviceType = SERVICE_RTP; /* TODO: H323 also possible. Parse SIP */
  u_short   proto  = IPPROTO_UDP;      /* TODO: Always UDP? Parse this out of SIP? */

#ifdef DEBUG_SIP
  {
    char buf[256], buf1[256];

    printf("SIP Media flow: %s:%d -> %s:%d\n", 
	   _intoa(a_addr, buf, sizeof buf), a_port,
	   _intoa(b_addr, buf1, sizeof buf1), b_port);
  }
#endif

  /* Check to see if this flow exists */
  idx = getHashIdx(npctxt, a_addr, a_port, b_addr, b_port);
  obkt = npctxt->hash[idx];

  while(obkt != NULL) {
#ifdef ENABLE_MAGIC
    if(obkt->magic != 67) {
      printf("Error: magic error detected (%d)", obkt->magic);
    }
#endif
    if((bkt->proto == proto)
       && ((cmpIpAddress(obkt->src, a_addr) && cmpIpAddress(obkt->dst, b_addr) 
	    && (obkt->sport == a_port)  && (obkt->dport == b_port))
	   || (cmpIpAddress(obkt->src, b_addr) && cmpIpAddress(obkt->dst, a_addr)
	       && (obkt->sport == b_port)  && (obkt->dport == a_port)))) {
      /* Media flow exists */
      if (obkt->serviceType != serviceType) {
	if (serviceType == SERVICE_RTP && obkt->serviceType != serviceType) {
	  if (!obkt->rtp_a_stat) {
	    obkt->rtp_a_stat = malloc(sizeof(rtp_stat_t));
	  }
	  memset(obkt->rtp_a_stat, 0, sizeof obkt->rtp_a_stat);
	  obkt->rtp_a_stat->min_jitter = 9999.;
	  if (!obkt->rtp_b_stat) {
	    obkt->rtp_b_stat = malloc(sizeof(rtp_stat_t));
	  }
	  memset(obkt->rtp_b_stat, 0, sizeof obkt->rtp_b_stat);
	  obkt->rtp_b_stat->min_jitter = 9999.;
	}
	obkt->serviceType = serviceType;
      }
      return;
    }
    obkt = obkt->next;
  }
  /* Media flow does not exist. Make a cache flow */
  memset(&tmpbkt, 0, sizeof tmpbkt);
  tmpbkt.src = a_addr;
  tmpbkt.sport = a_port;
  tmpbkt.dst = b_addr;
  tmpbkt.dport = b_port;
  tmpbkt.proto = proto;
  tmpbkt.serviceType = serviceType;
    
  /* FIXME: Shouldn't we use simulated time instead? */
  cacheBucket = cacheFlow(npctxt, &tmpbkt, time(NULL));
  addToList(cacheBucket, &npctxt->hash[idx]);
}

#ifdef DEBUG_SIP
static void 
trace_sip(struct hashBucket *bkt, u_int8_t *payload, u_int8_t *eol, sip_msg_type msg_type)
{
  char buf[1024];
  char tag[256];
  memset(tag, 0, sizeof tag);
  if (msg_type == sip_invite) {
    strcpy(tag, "SIP INVITE");
  } else if (strncmp((char *)payload, "SIP", strlen("SIP")) == 0) {
    strncpy(tag, (char *)payload, MIN((unsigned)(eol-payload), sizeof(tag)));
  } else {
    strcpy(tag, "SIP ");
    strncat(tag, (char *)payload, MIN((unsigned)(eol-payload), sizeof(tag)-4));
  }
  printf("%s %s:%d ", tag, _intoa(bkt->src, buf, sizeof(buf)), bkt->sport);
  printf("-> %s:%d ",  _intoa(bkt->dst, buf, sizeof(buf)), bkt->dport);
}
#endif


static void
sip_parse(np_ctxt_t *npctxt, u_int8_t *payload, u_int16_t payloadLen, 
	 struct hashBucket *bkt)
{
  /* Only audio media supported yet */
  const char *nm = "\012m=audio";
  const char *nc =  "\012c=IN";
  const char *nid = "\012Call-ID:";
  const char *nii = "\012i:";
  const char *sip_20 = "SIP/2.0 ";
  char *pm;
  char *pc;
  char *pi;
  int port;
  int respcode;
  char *pr;
  char *pt = NULL;
  unsigned i, ipver;
  char buf[64];
  char timestr[256];
  char call_id [256];
  struct hostent *hostEnt;
  struct in_addr addr;
  IpAddress b_addr;

  sip_msg_type msg_type;

  if (!payload || (payloadLen == 0))
	  return;

  time_t now = time(NULL);
  strftime(timestr, sizeof timestr, "%F %T", localtime(&now));

  /* Look for INVITE, PROGRESS & OK. Log others */
  /* FIXME: Give up and release resources for anything SIP/2.0 300 and up. */
  u_int8_t *eol;
  for (eol = payload; *eol && *eol != '\n'; eol++);
  if (*(eol-1) == 015)
    eol--;
  msg_type = sip_other;

#ifdef DEBUG_SINGLE_IP
  /* Some operators does weird things with ports */
  {
    char *ipstr = "192.168.1.3";
    u_int32_t naddr;
    IpAddress addr;

    inet_pton(AF_INET, per_arne, &naddr);
    addr.ipType.ipv4 = ntohl(naddr);
    addr.ipVersion = 4;
    if (cmpIpAddress(bkt->src, addr) || cmpIpAddress(bkt->dst, addr)) {
      trace_sip(bkt, payload, eol, msg_type);
      printf ("\nDSI: %s\n%s ==>\n%s\n<==\n", "Watching IP %s", ipstr, timestr, payload);
      
    }
  }
#endif

  if (strncmp((char *)payload, "INVITE", strlen("INVITE")) == 0) {
    msg_type = sip_invite;	/* Is an invite */
  } else if (strncmp((char *)payload, "CANCEL", strlen("CANCEL")) == 0) {
    msg_type = sip_giveup;	/* Is a cancel */
  } else if (strncmp((char *)payload, sip_20, strlen(sip_20)) == 0) {
    pr = (char *)payload + strlen(sip_20);
    respcode = atoi(pr);
    if (respcode == 183) {
      msg_type = sip_progress;	/* Is a progress */
    } else if (respcode == 200) {
      msg_type = sip_ok;		/* Is an OK */
    } else if (respcode > 300) {
      msg_type = sip_giveup;	 /* Is a reject */
    }
  }
  if (msg_type == sip_other) {
    return;
  }

  /* Look for Call-Id */
  pi = strstr((const char *)payload, nid);
  if (pi) {
    pi += strlen(nid);
  } else {
    pi = strstr((const char *)payload, nii);
    if (pi) {
      pi += strlen(nii);
    }
  }
  i = 0;
  if (pi) {
    for (; isspace(*pi); pi++) {}
    for (; i < (sizeof call_id - 1) && !isspace(*pi); i++) {
      call_id[i] = *pi++;
    }
  }
  call_id[i] = '\0';
  if (!call_id[0]) {
#ifdef DEBUG_SIP
    trace_sip(bkt, payload, eol, msg_type);
    printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "No Call-ID", timestr, payload);
#endif
    return;
  }

  if (bkt->sip_rtp_status == SIP_RTP_A_KNOWN && msg_type == sip_giveup && 
      bkt->sip_call_id && strcmp (bkt->sip_call_id, call_id) == 0) {
    /* Call we are tracking is terminated */
    bkt->sip_rtp_status = SIP_RTP_UNKNOWN;
    memset(&bkt->sip_rtp_a_addr, 0, sizeof bkt->sip_rtp_a_addr);
    bkt->sip_rtp_a_port = 0;
    free(bkt->sip_call_id);
    bkt->sip_call_id = NULL;
#ifdef DEBUG_SIP
    trace_sip(bkt, payload, eol, msg_type);
    printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "Setup terminated", timestr, payload);
#endif
    return;
  }

  pm = strstr((const char *)payload, nm);
  pc = strstr((const char *)payload, nc);

  /* Assume that "m=audio" and "c=" are in the same packet */
  if (!(pm && pc && *pm && *pc &&
	(pm - (char *) payload) <= (int) (payloadLen - strlen(nm)) &&
	(pc - (char *) payload) <= (int) (payloadLen - strlen(nc)))) {
#ifdef DEBUG_SIP
    /* Trace if media and address are supposed to be in the packet */
    if (msg_type == sip_invite ||
	(((msg_type == sip_ok || msg_type == sip_progress) &&  bkt->sip_rtp_status == SIP_RTP_A_KNOWN) &&
	 bkt->sip_call_id && strcmp (bkt->sip_call_id, call_id) == 0)) {
      trace_sip(bkt, payload, eol, msg_type);
      printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "Media/address not present", timestr, payload);
    }
#endif
    return;
  }

  /* Media, connection both found */
  for (pm += strlen(nm); isspace(*pm); pm++) {}
  /* Expecting a port number */
  port = strtol(pm, &pt, 10);
  if (!(pt > pm && isspace(*pt))) {
#ifdef DEBUG_SIP
    trace_sip(bkt, payload, eol, msg_type);
    printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "malformed 'm='", timestr, payload);
#endif
    return;			/* malformed 'm= ...' */
  }
  if (port < 0 || port >= 65535 || !(pt > pm && isspace(*pt))) {
#ifdef DEBUG_SIP
    trace_sip(bkt, payload, eol, msg_type);
    printf ("\nDBG: %s%d\n%s ==>\n%s\n<==\n", "Impossible port=", port, timestr, payload);
#endif
    return;			/* Impossible port */
  }

  for (pc += strlen(nc); isspace(*pc); pc++) {}
  /* Expecting "IP{4,6} addr or domain */
  if (strncmp(pc, "IP", 2) != 0) {
#ifdef DEBUG_SIP
    trace_sip(bkt, payload, eol, msg_type);
    printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "'IP' not present", timestr, payload);
#endif
    return;
  }
  pc += 2;
  if (*pc == '4')
    ipver = 4;				/* IPv4 */
  else if (*pc == '6')
    ipver = 6;				/* IPv6 */
  else {
#ifdef DEBUG_SIP
    trace_sip(bkt, payload, eol, msg_type);
    printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "invalid IP version", timestr, payload);
#endif
    return;
  }

  if (ipver == 6) {
#ifdef DEBUG_SIP
    trace_sip(bkt, payload, eol, msg_type);
    printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "IPv6 not yet supported", timestr, payload);
#endif
    return;			/* IPv6 not yet supported */
  }

  for (pc++; isspace(*pc); pc++) {}
  /* Resolve address */
  for(i = 0; i < (sizeof buf - 1) &&  !isspace(*pc); i++) {
    buf[i] = *pc++;
  }
  buf[i] = '\0';
  if (isdigit(buf[0])) {	/* Should be an address */
    if (inet_aton(buf, &addr) == 0) {
#ifdef DEBUG_SIP
      trace_sip(bkt, payload, eol, msg_type);
      printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "Invalid address", timestr, payload);
#endif
      return;
    }
  } else {			/* Domain */
    if((hostEnt = gethostbyname(buf)) == NULL) {
#ifdef DEBUG_SIP
      trace_sip(bkt, payload, eol, msg_type);
      printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "Invalid DNS name", timestr, payload);
#endif
      return;
    }
    memcpy(&addr, hostEnt->h_addr_list[0], hostEnt->h_length);
  }

  if (msg_type == sip_invite) {
    if (bkt->sip_rtp_status != SIP_RTP_UNKNOWN) {
      /* We don't (yet?) keep track of multiple outstanding invites */
#ifdef DEBUG_SIP
      trace_sip(bkt, payload, eol, msg_type);
      if (bkt->sip_call_id && strcmp (bkt->sip_call_id, call_id) == 0) {
	printf ("\n%s ==>\n%s\n<==\n", timestr, payload);
      } else {
	char buf[1024];
	printf ("\nDBG: %s", "New INVITE while tracking another");
	printf(" - %s:%d ", _intoa(bkt->src, buf, sizeof(buf)), bkt->sport);
	printf("-> %s:%d ", _intoa(bkt->dst, buf, sizeof(buf)), bkt->dport);
	printf ("\n%s ==>\n%s\n<==\n", timestr, payload);
      }
#endif
    } else if (port == 0) {
#ifdef DEBUG_SIP
      trace_sip(bkt, payload, eol, msg_type);
      printf ("\nDBG: %s%d\n%s ==>\n%s\n<==\n", "Impossible port=", port, timestr, payload);
#endif
    } else {
#ifdef DEBUG_SIP
      trace_sip(bkt, payload, eol, msg_type);
      printf ("media A addr: %s:%d\n", buf, port);
      printf ("%s ==>\n%s\n<==\n", timestr, payload);
#endif
      bkt->sip_call_id = strdup(call_id);
      bkt->sip_rtp_a_port = port;
      bkt->sip_rtp_a_addr.ipVersion = ipver;
      bkt->sip_rtp_a_addr.ipType.ipv4 = ntohl(addr.s_addr);
      bkt->sip_rtp_status = SIP_RTP_A_KNOWN;
    }
  } else if ((msg_type == sip_ok || msg_type == sip_progress) &&  bkt->sip_rtp_status == SIP_RTP_A_KNOWN) {
    if (!bkt->sip_call_id) {
#ifdef DEBUG_SIP
      trace_sip(bkt, payload, eol, msg_type);
      printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "A known and Call-ID NULL", timestr, payload);
#endif
      return;
    }
    if (port == 0) {
#ifdef DEBUG_SIP
      trace_sip(bkt, payload, eol, msg_type);
      printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "Media request refused", timestr, payload);
#endif
      return;
    }
    if (bkt->sip_call_id && strcmp (bkt->sip_call_id, call_id) == 0) {
#ifdef DEBUG_SIP
      trace_sip(bkt, payload, eol, msg_type);
      printf ("media B addr: %s:%d\n", buf, port);
      printf ("%s ==>\n%s\n<==\n", timestr, payload);
#endif
      b_addr.ipVersion = ipver;
      b_addr.ipType.ipv4 = ntohl(addr.s_addr);
      sip_media_flow_add(npctxt, bkt, b_addr, port);
      bkt->sip_rtp_status = SIP_RTP_UNKNOWN;
    } else {
#ifdef DEBUG_SIP
      trace_sip(bkt, payload, eol, msg_type);
      printf ("\nDBG: %s\n%s ==>\n%s\n<==\n", "Call-ID did not match", timestr, payload);
#endif
    }
  }
}


/* MPEG-TS stats initialization */
static void
init_mpegts_stats(HashBucket *bkt, unsigned long long stamp)
{
  int i;
  
  if (!bkt->mpegts_stat) {
    bkt->mpegts_stat = malloc(sizeof(mpegts_stat_t));
  }
  memset(bkt->mpegts_stat, 0, sizeof(mpegts_stat_t));
  for(i=0;i<8192; i++) {
    /*is ok, because 16 will never be seen. use it as a "first case" value */
    bkt->mpegts_stat->cc[i] = 16; 
  }
  bkt->mpegts_stat->local_clock = 0.0;
  bkt->mpegts_stat->last_realtime = double_time(stamp);
}


/* ******************************************************** */

static inline HashBucket *
getFreeBucket(np_ctxt_t *npctxt)
{
  HashBucket *bkt;

  pthread_mutex_lock(&purgedBucketsMutex);
  if(npctxt->purgedBuckets != NULL) {
    bkt = getListHead(&npctxt->purgedBuckets);
    npctxt->purgedBucketsLen--;
  } else {
    bkt = (HashBucket*)malloc(sizeof(HashBucket));
    if(bkt == NULL) {
      printf("ERROR: NULL bkt (not enough memory?)\n");
    } else {
      npctxt->bucketsAllocated++;
    }
  }
  pthread_mutex_unlock(&purgedBucketsMutex);
  if (bkt) {
    memset(bkt, 0, sizeof(HashBucket)); /* Reset bucket */
#ifdef ENABLE_MAGIC
    bkt->magic = 67;
#endif
  }
  return bkt;
}

/* ******************************************************** */

static inline void 
initFlow(np_ctxt_t *npctxt, HashBucket *bkt, 
	 u_short proto, u_char isFragment, u_short numPkts, u_char tos, u_int len, 
	 unsigned long long stamp, u_short ifindex, u_int8_t flags, 
	 u_int8_t icmpType, u_char *fingerprint,
	 u_char *payload, int payloadLen, u_int headerLen, u_int64_t v4_options, 
	 u_int64_t tcp_options, u_char ttl, u_int32_t seqnum, u_int is_pim, 
	 u_int16_t tcpWindowSize, u_char tcpWindowScale)
{
  int i;
  u_int32_t tcpWindowSize32 = -1;
  int isCached = isCacheBucket(bkt);

  bkt->ifindex = ifindex;

  if(npctxt->bitrateCalcEnabled!=0) {

    // Clear the "time slot" buffers that is used to efficiently find highest/lowest
    // average xfer amount for a period of time.
    // Clear all, also if only one will be used.
    for(i=0;i<BITRATE_COUNT; i++) {
      memset(bkt->src2dstBitrateAverager[i],  0xFF, sizeof(u_int32_t)*BITRATE_AVERAGER_SLOTS);
      memset(bkt->dst2srcBitrateAverager[i],  0xFF, sizeof(u_int32_t)*BITRATE_AVERAGER_SLOTS);
      bkt->src2dstBitrateLastUpdate[i] = stamp;
      bkt->dst2srcBitrateLastUpdate[i] = stamp;
      bkt->src2dstBitrateAverager[i][0]  = 0;
      bkt->dst2srcBitrateAverager[i][0]  = 0;
    }

    memset(bkt->src2dstRateMax, 0x00, 4*BITRATE_COUNT);
    memset(bkt->src2dstRateMin, 0xFF, 4*BITRATE_COUNT);
    memset(bkt->dst2srcRateMax, 0x00, 4*BITRATE_COUNT);
    memset(bkt->dst2srcRateMin, 0xFF, 4*BITRATE_COUNT);
    memset(bkt->src2dstBitrateAveragerPos, 0x00, 4*BITRATE_COUNT);
    memset(bkt->dst2srcBitrateAveragerPos, 0x00, 4*BITRATE_COUNT);

    updateBitrateCalculation(npctxt,bkt,len,stamp,0,0);
  }
  bkt->src2dst_last_sequence_number = seqnum;
  bkt->src2dst_num_packets_out_of_sequence = 0;
  bkt->dst2src_last_sequence_number = 0;
  bkt->dst2src_num_packets_out_of_sequence = 0;

  bkt->src2dstTcpwin_eff = 0;
  bkt->src2dstTcpwin_eff_seqnum = seqnum;
  bkt->src2dstTcpwin_eff_bytes = payloadLen;

  bkt->dst2srcTcpwin_eff = 0;
  bkt->dst2srcTcpwin_eff_seqnum = 0;
  bkt->dst2srcTcpwin_eff_bytes = 0;

  bkt->src2dstMinTTL = ttl;
  bkt->src2dstMaxTTL = ttl;
  bkt->dst2srcMinTTL = 0xFF;
  bkt->dst2srcMaxTTL = 0x00;

  bkt->src2dstTcpFlagsFirst = flags;
  bkt->dst2srcTcpFlagsFirst = (unsigned short)-1;

  if(npctxt->histPktSizeEnabled != 0)
    updatePacketSizeStats(npctxt,bkt,len,0);
  bkt->src2dstMinPktSize = len;
  bkt->src2dstMaxPktSize = len;

  if(bkt->src.ipVersion == 4) {
    bkt->optionsIPV4src2dst = v4_options;
    bkt->optionsIPV6src2dst = 0;
  } else {
    bkt->optionsIPV4src2dst = 0;
    bkt->optionsIPV6src2dst = 0; // N/I
  }  
  bkt->optionsIPV4dst2src = 0;
  bkt->optionsIPV6dst2src = 0;

  if(proto == IPPROTO_TCP)
    bkt->src2dstTcpOpt = tcp_options;
  else
    bkt->src2dstTcpOpt = 0;
  bkt->dst2srcTcpOpt = 0;

  bkt->src2dstOctetDeltaCount = len;
  bkt->dst2srcOctetDeltaCount = 0;
  //src2dstOctetTotalCount = len;
  //dst2srcOctetTotalCount = 0;

  if(npctxt->pktDistLengthStddevs>0) {
    bkt->src2dst_expval_pktdist_x   = 0;
    bkt->src2dst_expval_pktdist_x2  = 0;
    bkt->src2dst_expval_pktlength_x = len;
    bkt->src2dst_expval_pktlength_x2= len*len;

    bkt->dst2src_expval_pktdist_x   = 0;
    bkt->dst2src_expval_pktdist_x2  = 0;
    bkt->dst2src_expval_pktlength_x = 0;
    bkt->dst2src_expval_pktlength_x2= 0;
  }

  /* FIXME: SIP? RTP? */
  if(npctxt->rtcp_enabled != 0) {
    bkt->rtcp_jitter   = 0;
    bkt->rtcp_lostfrac = 0;
    bkt->rtcp_lostpkts = 0;
    bkt->rtcp_cycles   = 0;
    bkt->rtp_sniff_res = RTP_SNIFF_NOT_STARTED;
    bkt->rtp_sync_source = 0;
    bkt->rtp_last_sequence_number = 0;
    bkt->rtp_sequence_badness = 0;
    read_rtp_parameters((u_int8_t *)payload, payloadLen, bkt);
  }

  bkt->pim_count = 0;
  if(is_pim == 1) {
    bkt->pim_count = bkt->pim_count + 1;
  }

  /* Calculate src2dst payload length (payload length for ipv6). Only first packet. */
  bkt->src2dstPktlenIpv4 = 0;
  bkt->src2dstPayloadlenIpv6 = 0;
  bkt->dst2srcPktlenIpv4 = 0;
  bkt->dst2srcPayloadlenIpv6 = 0;
  if(bkt->src.ipVersion == 4)
    bkt->src2dstPktlenIpv4 = len;
  else
    bkt->src2dstPayloadlenIpv6 = payloadLen;

  if(bkt->src.ipVersion == 4 && proto == IPPROTO_TCP)
    bkt->headerlengthIPv4 = headerLen;
  else
    bkt->headerlengthIPv4 = 0;

  bkt->flowEndReason = FLOW_END_IDLE;

  bkt->firstSeenSent = bkt->lastSeenSent = stamp;
  bkt->firstSeenRcvd = bkt->lastSeenRcvd = 0;
  bkt->bytesSent += len;
  bkt->pktSent = bkt->pktSent + numPkts;
  if(isFragment) NPROBE_FD_SET(FLAG_FRAGMENTED_PACKET_SRC2DST, &(bkt->flags));
  if(proto == IPPROTO_TCP)
    updateTcpFlags(bkt, 0, stamp, flags, fingerprint, tos);
  else if((proto == IPPROTO_UDP) || (proto == IPPROTO_ICMP))
    updateApplLatency(proto, bkt, 0, stamp, icmpType);

  if(npctxt->maxPayloadLen > 0)
    setPayload(npctxt, bkt, payload, payloadLen, 0);
  bkt->src2dstTcpFlags |= flags;

  /* Increase num of observed flows. We don't update the number of flows
   * when traffic is discovered in the other direction. */
  bkt->src2dstflowid = (uint32_t)npctxt->numObservedFlows;
  bkt->dst2srcflowid = 0;
  npctxt->numObservedFlows = npctxt->numObservedFlows + 1;

  bkt->src2dstTcpWindowScale = tcpWindowScale;
  bkt->dst2srcTcpWindowScale = (u_char)-1;
  if(tcpWindowScale == (u_char)-1) {
    tcpWindowScale = 0;
  }
  tcpWindowSize32 = ((u_int32_t)tcpWindowSize)<<tcpWindowScale;


  bkt->src2dstTcpWindowSize = tcpWindowSize;
  bkt->dst2srcTcpWindowSize = 0;
  
  bkt->src2dstTcpWindowMax = tcpWindowSize32;
  bkt->src2dstTcpWindowMin = tcpWindowSize32;
  bkt->dst2srcTcpWindowMax = (u_int32_t)0;
  bkt->dst2srcTcpWindowMin = (u_int32_t)-1;

  if (!isCached) {
    if (npctxt->serviceClassification && bkt->serviceType == SERVICE_UNKNOWN) {
      bkt->serviceType = serviceClassification((struct np_ctxt_t *)npctxt, proto, bkt->sport, bkt->dport,
					       payload, payloadLen);
    }
    if (bkt->serviceType == SERVICE_SIP && bkt->sip_rtp_status != SIP_RTP_AB_KNOWN) {
      /* Extract endpoint info */
      sip_parse(npctxt, payload, payloadLen, bkt);
    }
  }
  
  if (bkt->serviceType != SERVICE_SIP) {
    bkt->sip_rtp_status = SIP_RTP_UNKNOWN;
    memset(&bkt->sip_rtp_a_addr, 0, sizeof bkt->sip_rtp_a_addr);
    bkt->sip_rtp_a_port = 0;
    bkt->sip_call_id    = NULL;
  }

  /* MPEG-TS stats initialization */
  if (bkt->serviceType == SERVICE_MPEGTS) {
    init_mpegts_stats(bkt, stamp);
  }

  if (bkt->serviceType == SERVICE_RTP) {
    if (!bkt->rtp_a_stat) {
      bkt->rtp_a_stat = malloc(sizeof(rtp_stat_t));
    }
    memset(bkt->rtp_a_stat, 0, sizeof bkt->rtp_a_stat);
    bkt->rtp_a_stat->min_jitter = 9999.;
    if (!bkt->rtp_b_stat) {
      bkt->rtp_b_stat = malloc(sizeof(rtp_stat_t));
    }
    memset(bkt->rtp_b_stat, 0, sizeof bkt->rtp_b_stat);
    bkt->rtp_b_stat->min_jitter = 9999.;
  }


}

/* ******************************************************** */

/*
 * cached flows were introduced in order to make service classification 
 * useful. For instance, a bittorrent flow is classified based on strings
 * seen early in the flow. Frequently, the flow will expire on active timeout
 * before it has completed. Cached flows are used to remember the service
 * classification, so that it can be reused when more activity is seen on the 
 * flow. In the future, other parameters can be remembered in the same way.
 * Cached flows are never exported. They are purged once cacheTimeout is 
 * exceeded, unless they have been uncached (revived) before this happens.
 * To avoid excessive memory use, expired flows are only cached when this is
 * useful. For now, this means when the service type has been identified.
 */

static int
flowNeedsCaching(np_ctxt_t *npctxt, HashBucket *myBucket)
{
  return (!isCacheBucket(myBucket) &&
	  npctxt->serviceClassification && 
	  ((myBucket->serviceType == SERVICE_TORRENT) ||
	   (myBucket->serviceType == SERVICE_RTP) ||
	   ((myBucket->serviceType == SERVICE_SIP) && (myBucket->sip_rtp_status == SIP_RTP_A_KNOWN))));
} 

/* ******************************************************** */

static HashBucket *
cacheFlow(np_ctxt_t *npctxt, HashBucket *bkt, time_t time)
{
  HashBucket *cacheBkt = getFreeBucket(npctxt);
#ifdef DEBUG_CACHING
  {
    char buf[256], buf1[256];

    printf("caching flow [%4s] %s:%d -> %s:%d, srv=%d\n",
	   proto2name(bkt->proto),
	   _intoa(bkt->src, buf, sizeof(buf)), (int)bkt->sport,
	   _intoa(bkt->dst, buf1, sizeof(buf1)), (int)bkt->dport,
	   (int)bkt->serviceType);
  }
#endif
#ifdef DEBUG_JK
  npctxt->cacheCnt++;
  if (bkt->serviceType == SERVICE_TORRENT) { npctxt->torrentCnt++; }
  if (bkt->serviceType == SERVICE_RTP) { npctxt->rtpCnt++; }
#endif  
  /* Cache bookkeeping */
  cacheBkt->enteredCache = ((long long) time) << 32;
  NPROBE_FD_SET(FLAG_CACHE_BUCKET, &(cacheBkt->flags));

  /* Basic attributes */
  memcpy(&cacheBkt->src, &bkt->src, sizeof(IpAddress));
  memcpy(&cacheBkt->dst, &bkt->dst, sizeof(IpAddress));
  cacheBkt->proto = bkt->proto;
  cacheBkt->sport = bkt->sport;
  cacheBkt->dport = bkt->dport; 
  cacheBkt->ifindex = bkt->ifindex;

  /* QoS attibutes */
  cacheBkt->serviceType = bkt->serviceType;
  if (bkt->sip_call_id) {
    cacheBkt->sip_call_id = strdup(bkt->sip_call_id);
  } else {
    cacheBkt->sip_call_id = NULL;
  }
  cacheBkt->sip_rtp_status = bkt->sip_rtp_status;
  cacheBkt->sip_rtp_a_addr = bkt->sip_rtp_a_addr;
  cacheBkt->sip_rtp_a_port = bkt->sip_rtp_a_port;
  
  /* TODO: Other QoS attributes? */
  
  return cacheBkt;
}

/* ******************************************************** */

static void
uncacheFlow(np_ctxt_t *npctxt, HashBucket *bkt,
	    u_short proto, u_char isFragment, u_short numPkts, u_char tos, u_int len, 
	    unsigned long long stamp, u_int8_t flags, u_int8_t icmpType,
	    u_char *fingerprint,
	    u_char *payload, int payloadLen, u_int headerLen, u_int64_t v4_options, 
	    u_int64_t tcp_options, u_char ttl, u_int32_t seqnum, u_int is_pim, 
	    u_int16_t tcpWindowSize, u_char tcpWindowScale)
{
#ifdef DEBUG_CACHING
  {
    char buf[256], buf1[256];

    printf("uncaching flow [%4s] %s:%d -> %s:%d, srv=%d\n",
	   proto2name(bkt->proto),
	   _intoa(bkt->src, buf, sizeof(buf)), (int)bkt->sport,
	   _intoa(bkt->dst, buf1, sizeof(buf1)), (int)bkt->dport,
	   (int)bkt->serviceType);
  }
#endif
#ifdef DEBUG_JK
  npctxt->uncacheCnt++;
#endif

  /* Initialize a new flow, basically creates a new bucket */
  initFlow(npctxt, bkt, proto, isFragment, numPkts, tos, len, stamp, 
	   bkt->ifindex,
	   flags, icmpType, fingerprint, payload, payloadLen, headerLen,
	   v4_options, tcp_options, ttl, seqnum, is_pim, 
	   tcpWindowSize, tcpWindowScale);
	
  NPROBE_FD_CLR(FLAG_CACHE_BUCKET, &(bkt->flags));
}

/* ****************************************************** */

/*
   1 - equal
   0 - different
*/
static int 
cmpIpAddress(IpAddress src, IpAddress dst) {
  if(src.ipVersion != dst.ipVersion) return(0);

  if(src.ipVersion == 4) {
    return(src.ipType.ipv4 == dst.ipType.ipv4 ? 1 : 0);
  } else {
    return(!memcmp(&src.ipType.ipv6, &dst.ipType.ipv6, sizeof(struct in6_addr)));
  }
}

void addPktToHash(np_ctxt_t *npctxt,
		  u_short proto,
		  u_char isFragment,
		  u_short numPkts,
		  u_char tos,
		  IpAddress src,
		  u_short sport,
		  IpAddress dst,
		  u_short dport,
		  u_int  len,
		  unsigned long long stamp,
		  u_short  ifindex,
		  u_int8_t flags,
		  u_int8_t icmpType,
		  u_char *fingerprint,
		  u_char *payload,
		  int payloadLen,
		  u_int headerLen, u_int64_t v4_options, 
		  u_int64_t tcp_options, u_char ttl,
		  u_int32_t seqnum, u_int32_t acknum,
		  u_int is_pim, u_int16_t tcpWindowSize, 
		  u_char tcpWindowScale) {
  u_int32_t n=0, mutexIdx, idx; /* (src+dst+sport+dport) % hashSize; */
  HashBucket *bkt;
  u_int32_t tcpWindowSize32 = -1;
  int i;
  unsigned long long ts;
  unsigned long ts_sec, ts_usec; // Time since last packets
  int direction;

  idx = getHashIdx(npctxt, src, sport, dst, dport);

  actTime = stamp;

#ifdef DEBUG_PKT
  {
    char buf[256], buf1[256];

    printf("[%4s] %s:%d -> %s:%d [len=%u][payloadLen=%d][idx=%d]\n",
	   proto2name(proto),
	   _intoa(src, buf, sizeof(buf)), (int)sport,
	   _intoa(dst, buf1, sizeof(buf1)), (int)dport,
	   len, payloadLen, idx);
  }
#endif

  mutexIdx = idx % MAX_HASH_MUTEXES;
  pthread_mutex_lock(&hashMutex[mutexIdx]);

  bkt = npctxt->hash[idx];

  while(bkt != NULL) {
#ifdef ENABLE_MAGIC
    if(bkt->magic != 67) {
      printf("Error: magic error detected (%d)", bkt->magic);
    }
#endif

    if((bkt->proto == proto)
       && ((cmpIpAddress(bkt->src, src) && cmpIpAddress(bkt->dst, dst) && (bkt->sport == sport)  && (bkt->dport == dport))
	   || (cmpIpAddress(bkt->src, dst) && cmpIpAddress(bkt->dst, src) && (bkt->sport == dport)  && (bkt->dport == sport)))) {

      if (isCacheBucket(bkt)) {
	uncacheFlow(npctxt, bkt, proto, isFragment, numPkts, tos, len, stamp, 
		    flags, 
		    icmpType, fingerprint, payload, payloadLen, headerLen,
		    v4_options, tcp_options, ttl, seqnum, is_pim, 
		    tcpWindowSize, tcpWindowScale);      
      }

      if(bkt->src.ipType.ipv4 == src.ipType.ipv4) {
	direction = 0;
	ts = bkt->lastSeenSent;
      } else {
	direction = 1;
	ts = bkt->lastSeenRcvd; // may be 0 if none received
      }

      if(bkt->serviceType==SERVICE_UNKNOWN && npctxt->serviceClassification) {
	bkt->serviceType = serviceClassification((struct np_ctxt_t *)npctxt, proto, sport, dport,
						 payload, payloadLen);
	if (bkt->serviceType == SERVICE_MPEGTS) {
	  init_mpegts_stats(bkt, stamp);
	}
      }
      if (bkt->serviceType == SERVICE_SIP && bkt->sip_rtp_status != SIP_RTP_AB_KNOWN) {
	/* Extract endpoint info */
	sip_parse(npctxt, payload, payloadLen, bkt);
      }

      if (bkt->serviceType == SERVICE_MPEGTS) {
	/* Entry point for lykkebo */
	split_parse_mpegts((char *)payload, payloadLen, bkt, stamp, direction);
      }

      if(is_pim == 1 && bkt->pim_count < 255) {
	bkt->pim_count = bkt->pim_count + 1;
      }
      
      if(npctxt->rtcp_enabled != 0)
	read_rtp_parameters((u_int8_t *)payload, payloadLen, bkt); /* FIXME: Remove? */
      if (bkt->serviceType == SERVICE_RTP) {
	rtp_parse((u_int8_t *)payload, payloadLen, direction, stamp, bkt);
      }

      /*
       * Calculate time since last package. This is used both for
       * calculating the packet-distance histogram, and calculating
       * std.deviation for packet distance.
       */
      if(ts != 0 && (npctxt->histPktDistEnabled || npctxt->pktDistLengthStddevs>0)) {
	
	// timestamp has format:
	//    sec = (stamp >> 32) & 0xFFFFFFFFl
	//   usec = (stamp&0xFFFFFFFFl)/4295l
	// (see mapinicdrv.c)
	// we only want to deal with the usec part.
	
	ts = stamp-ts;
	ts_sec = (ts>>32)&0xFFFFFFFFl;
	ts_usec= (ts&0xFFFFFFFFl)/4295l;

	if(npctxt->histPktDistEnabled) {
	  unsigned int  nslot = PKTDIST_HISTOGRAM_SLOTS-1;
	  
	  if(ts_sec==0l) { // ignore everything from 1sec and up
	    for(i=0; i<PKTDIST_HISTOGRAM_SLOTS; i++) {
	      if(ts_usec <= npctxt->histPktDistBucket[i]) {
		nslot = i;
		break;
	      }
	    }	  
	  }
	  
	  if(direction == 0)
	    bkt->src2dstPktDistHistogram[nslot]++;
	  else
	    bkt->dst2srcPktDistHistogram[nslot]++;
	}
      }


      if(direction == 0) {
	bkt->bytesSent += len;
	bkt->pktSent = bkt->pktSent + numPkts;
	bkt->lastSeenSent = stamp;
	if(isFragment) NPROBE_FD_SET(FLAG_FRAGMENTED_PACKET_SRC2DST, &(bkt->flags));
	if(proto == IPPROTO_TCP)
	  updateTcpFlags(bkt, direction, stamp, flags, fingerprint, tos);
	else if((proto == IPPROTO_UDP) || (proto == IPPROTO_ICMP))
	  updateApplLatency(proto, bkt, direction, stamp, icmpType);

	/* Set local window scaling option based on history */
	if(tcpWindowScale != (u_char)-1) {
	  bkt->src2dstTcpWindowScale = tcpWindowScale;
	} else if(bkt->src2dstTcpWindowScale != (u_char)-1) {
	  tcpWindowScale = bkt->src2dstTcpWindowScale;
	} else {
	  tcpWindowScale = 0;
	}
	tcpWindowSize32 = ((u_int32_t)tcpWindowSize)<<tcpWindowScale;

	if(npctxt->maxPayloadLen > 0)
	  setPayload(npctxt, bkt, payload, payloadLen, 0);
	bkt->src2dstTcpFlags |= flags; /* Do not move this line before updateTcpFlags(...) */

	if(npctxt->histPktSizeEnabled != 0)
	  updatePacketSizeStats(npctxt,bkt,len,0);
	bkt->src2dstMinPktSize = _min(bkt->src2dstMinPktSize,len);
	bkt->src2dstMaxPktSize = _max(bkt->src2dstMaxPktSize,len);

	if(npctxt->bitrateCalcEnabled!=0) {	
	  updateBitrateCalculation(npctxt,bkt,len, stamp,0,0);
	}

	bkt->src2dstOctetDeltaCount = bkt->src2dstOctetDeltaCount + len;

	if(src.ipVersion == 4)
	  bkt->optionsIPV4src2dst |= v4_options;
	
	if(proto == IPPROTO_TCP)
	  bkt->src2dstTcpOpt |= tcp_options;


	if(npctxt->pktDistLengthStddevs>0 && ts != 0) {
	  bkt->src2dst_expval_pktdist_x   = bkt->src2dst_expval_pktdist_x   + ts_usec;
	  bkt->src2dst_expval_pktdist_x2  = bkt->src2dst_expval_pktdist_x2  + ts_usec*ts_usec;
	  bkt->src2dst_expval_pktlength_x = bkt->src2dst_expval_pktlength_x + len;
	  bkt->src2dst_expval_pktlength_x2= bkt->src2dst_expval_pktlength_x2+ len*len;
	}

	if(ttl < bkt->src2dstMinTTL)
	  bkt->src2dstMinTTL = ttl;
	if(ttl > bkt->src2dstMaxTTL)
	  bkt->src2dstMaxTTL = ttl;

	/* bkt->src2dstTcpWindowSize=tcpWindowSize;--only register first pkt*/	
	if(bkt->src2dstTcpWindowMax < tcpWindowSize32)
	  bkt->src2dstTcpWindowMax = tcpWindowSize32;
	if(bkt->src2dstTcpWindowMin > tcpWindowSize32)
	  bkt->src2dstTcpWindowMin = tcpWindowSize32;

	/* Calculate packets out of sequence for various transport protocols.*/
	switch(proto) {
	case IPPROTO_TCP:
	  if(bkt->src2dst_last_sequence_number > seqnum &&
	     !(bkt->src2dst_last_sequence_number > 0xAFFFFFFF 
	       && seqnum < 0x3FFFFFFF)) {
	    /* seqnum has lower ID than expected */
	    bkt->src2dst_num_packets_out_of_sequence++;
	    
	  } else {
	    /* Ordered, or early delivery. */
	    bkt->src2dst_last_sequence_number = seqnum;
	  }
	  
	  /* Calculate effective TCP window:
	     Note that TCP acknum is next expected byte.
	     Calculating the effective TCP window is based on that
	     the window will be equal to the number of packets between
	     us and the destination. If we (the probe) are close to the
	     destination, this will be small (low latency).
	  */
	  if(acknum != 0 && bkt->dst2srcTcpwin_eff_seqnum != 0 && 
	     (acknum > bkt->dst2srcTcpwin_eff_seqnum ||
	     (acknum < 0x3FFFFFFF && bkt->dst2srcTcpwin_eff_seqnum > 0xAFFFFFFF))) {
	    if(bkt->dst2srcTcpwin_eff_bytes > bkt->dst2srcTcpwin_eff)
	      bkt->dst2srcTcpwin_eff = bkt->dst2srcTcpwin_eff_bytes;
	    bkt->dst2srcTcpwin_eff_seqnum = 0;
	  }
	  if(bkt->src2dstTcpwin_eff_seqnum == 0) {
	    bkt->src2dstTcpwin_eff_seqnum = seqnum;
	    bkt->src2dstTcpwin_eff_bytes = payloadLen;
	  } else
	    bkt->src2dstTcpwin_eff_bytes = bkt->src2dstTcpwin_eff_bytes + payloadLen;
	  
	  break;
	};	

      } else {
	bkt->bytesRcvd += len;
	bkt->pktRcvd = bkt->pktRcvd + numPkts;
	if(bkt->firstSeenRcvd == 0)
	  bkt->firstSeenRcvd = stamp;
	bkt->lastSeenRcvd = stamp;
	if(isFragment) NPROBE_FD_SET(FLAG_FRAGMENTED_PACKET_DST2SRC, &(bkt->flags));
	if(proto == IPPROTO_TCP)
	  updateTcpFlags(bkt, direction, stamp, flags, fingerprint, tos);
	else if((proto == IPPROTO_UDP) || (proto == IPPROTO_ICMP))
	  updateApplLatency(proto, bkt, direction, stamp, icmpType);

	/* Set local window scaling option based on history */
	if(tcpWindowScale != (u_char)-1) {
	  bkt->dst2srcTcpWindowScale = tcpWindowScale;
	} else if(bkt->dst2srcTcpWindowScale != (u_char)-1) {
	  tcpWindowScale = bkt->dst2srcTcpWindowScale;
	} else {
	  tcpWindowScale = 0;
	}
	tcpWindowSize32 = ((u_int32_t)tcpWindowSize)<<tcpWindowScale;

	if(npctxt->maxPayloadLen > 0)
	  setPayload(npctxt, bkt, payload, payloadLen, 1);
	bkt->dst2srcTcpFlags |= flags; /* Do not move this line before updateTcpFlags(...) */
	if(bkt->dst2srcTcpFlagsFirst == (unsigned short)-1) {
	  // Only update for first packet.
	  bkt->dst2srcTcpFlagsFirst = flags;
	}
	if(npctxt->histPktSizeEnabled != 0)
	  updatePacketSizeStats(npctxt,bkt,len,1);
	if (bkt->dst2srcMaxPktSize == 0) { /* dst2src min/max not yet set */
	  bkt->dst2srcMinPktSize = len;
	}
	bkt->dst2srcMinPktSize = _min(bkt->dst2srcMinPktSize,len);
	bkt->dst2srcMaxPktSize = _max(bkt->dst2srcMaxPktSize,len);
	if(npctxt->bitrateCalcEnabled!=0) {	
	  updateBitrateCalculation(npctxt,bkt,len, stamp,1,0);
	}

	bkt->dst2srcOctetDeltaCount = bkt->dst2srcOctetDeltaCount + len;

	if(src.ipVersion == 4)
	  bkt->optionsIPV4dst2src |= v4_options;

	if(proto == IPPROTO_TCP)
	  bkt->dst2srcTcpOpt |= tcp_options;

	/* calculate first packet's size on dst2src. Src2dst already calculated. */
	if(bkt->dst2srcPktlenIpv4==0 && bkt->dst2srcPayloadlenIpv6==0) {
	  if(src.ipVersion == 4)
	    bkt->dst2srcPktlenIpv4 = len;
	  else
	    bkt->dst2srcPayloadlenIpv6 = payloadLen;
	}

	if(npctxt->pktDistLengthStddevs>0 && ts != 0) {
	  bkt->dst2src_expval_pktdist_x   = bkt->dst2src_expval_pktdist_x   + ts_usec;
	  bkt->dst2src_expval_pktdist_x2  = bkt->dst2src_expval_pktdist_x2  + ts_usec*ts_usec;
	  bkt->dst2src_expval_pktlength_x = bkt->dst2src_expval_pktlength_x + len;
	  bkt->dst2src_expval_pktlength_x2= bkt->dst2src_expval_pktlength_x2+ len*len;
	}

	if(ttl < bkt->dst2srcMinTTL)
	  bkt->dst2srcMinTTL = ttl;
	if(ttl > bkt->dst2srcMaxTTL)
	  bkt->dst2srcMaxTTL = ttl;

	/* only register tcp window size for first pkt, per ipfix-info */
	if(bkt->dst2srcTcpWindowSize == 0)
	  bkt->dst2srcTcpWindowSize = tcpWindowSize;
	if(bkt->dst2srcTcpWindowMax < tcpWindowSize32)
	  bkt->dst2srcTcpWindowMax = tcpWindowSize32;
	if(bkt->dst2srcTcpWindowMin > tcpWindowSize32)
	  bkt->dst2srcTcpWindowMin = tcpWindowSize32;

	/* Calculate packets out of sequence for various transport protocols.*/
	switch(proto) {
	case IPPROTO_TCP:
	  if(bkt->dst2src_last_sequence_number != 0) {
	    if(bkt->dst2src_last_sequence_number > seqnum &&
	       !(bkt->dst2src_last_sequence_number > 0xAFFFFFFF 
		 && seqnum < 0x3FFFFFFF)) {
	      /* Packet has lower ID than expected */
	      bkt->dst2src_num_packets_out_of_sequence++;
	    } else {
	      /* Ordered, or early delivery. */
	      bkt->dst2src_last_sequence_number = seqnum;
	    }
	  } else
	    bkt->dst2src_last_sequence_number = seqnum;
	  
	  /* Calculate effective TCP window:
	     Note that TCP acknum is next expected byte.
	     Calculating the effective TCP window is based on that
	     the window will be equal to the number of packets between
	     us and the destination. If we (the probe) are close to the
	     destination, this will be small (low latency).
	  */
	  if(acknum != 0 && bkt->src2dstTcpwin_eff_seqnum != 0 && 
	     (acknum > bkt->src2dstTcpwin_eff_seqnum ||
	     (acknum < 0x3FFFFFFF && bkt->src2dstTcpwin_eff_seqnum > 0xAFFFFFFF))) {
	    if(bkt->src2dstTcpwin_eff_bytes > bkt->src2dstTcpwin_eff)
	      bkt->src2dstTcpwin_eff = bkt->src2dstTcpwin_eff_bytes;
	    bkt->src2dstTcpwin_eff_seqnum = 0;
	  }
	  if(bkt->dst2srcTcpwin_eff_seqnum == 0) {
	    bkt->dst2srcTcpwin_eff_seqnum = seqnum;
	    bkt->dst2srcTcpwin_eff_bytes = payloadLen;
	  } else
	    bkt->dst2srcTcpwin_eff_bytes = bkt->dst2srcTcpwin_eff_bytes + payloadLen;
	  
	  break;
	};
	
	
	if(bkt->dst2srcflowid==0) {
	  bkt->dst2srcflowid = npctxt->numObservedFlows;
	  npctxt->numObservedFlows = npctxt->numObservedFlows + 1;
	}

      }
      
      pthread_mutex_unlock(&hashMutex[mutexIdx]);
      npctxt->sumBucketSearch += n;
      return;
      /* ******** END OF COMMONLY USED PATH ******* */
    } else {
      /* Bucket not found yet */
      n++;
      bkt = bkt->next;

      if(n > npctxt->hashSize) {
	printf("Error: LOOP detected");
	if (bkt)
	  bkt->next = NULL;
	break;
      }
    }
  } /* while */

  pthread_mutex_unlock(&hashMutex[mutexIdx]);

#ifdef DEBUG_EXPORT
  printf("Adding new bucket\n");
#endif

  if(n > npctxt->maxBucketSearch) npctxt->maxBucketSearch = n;
  npctxt->sumBucketSearch += n;

  bkt = getFreeBucket(npctxt);
  if (!bkt)
    return;

  memcpy(&bkt->src, &src, sizeof(IpAddress));
  memcpy(&bkt->dst, &dst, sizeof(IpAddress));
  bkt->proto = proto;
  bkt->sport = sport, bkt->dport = dport;

  /* Lock must be acquired here. initFlow calls sip_parse, which may add a 
   * flow record (for the media stream) to the hash */
  /* FIXME: This only works when  MAX_HASH_MUTEXES is 1. If > 1, this mutex 
   * most of the time won't protect sip_parse */
  pthread_mutex_lock(&hashMutex[mutexIdx]);
  initFlow(npctxt, bkt, proto, isFragment, numPkts, tos, len, stamp, ifindex, 
	   flags, icmpType, fingerprint, payload, payloadLen, headerLen,
	   v4_options, tcp_options, ttl, seqnum, is_pim, 
	   tcpWindowSize, tcpWindowScale);

  /* Put the bucket on top of the list */
  addToList(bkt, &npctxt->hash[idx]);
  pthread_mutex_unlock(&hashMutex[mutexIdx]);

  if(npctxt->traceMode == 2) {
    char buf[256], buf1[256];

    printf("New: [%s] %s:%d -> %s:%d\n",
	   proto2name(proto), _intoa(src, buf, sizeof(buf)), sport,
	   _intoa(dst, buf1, sizeof(buf1)), dport);
  }
}

/* ****************************************************** */

void printICMPflags(u_int32_t flags, char *icmpBuf, int icmpBufLen) {
  snprintf(icmpBuf, icmpBufLen, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
	   NPROBE_FD_ISSET(NPROBE_ICMP_ECHOREPLY, &flags)     ? "[ECHO REPLY]" : "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_UNREACH, &flags)       ? "[UNREACH]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_SOURCEQUENCH, &flags)  ? "[SOURCE_QUENCH]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_REDIRECT, &flags)      ? "[REDIRECT]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_ECHO, &flags)          ? "[ECHO]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_ROUTERADVERT, &flags)  ? "[ROUTERADVERT]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_ROUTERSOLICIT, &flags) ? "[ROUTERSOLICIT]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_TIMXCEED, &flags)      ? "[TIMXCEED]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_PARAMPROB, &flags)     ? "[PARAMPROB]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_TSTAMP, &flags)        ? "[TIMESTAMP]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_TSTAMPREPLY, &flags)   ? "[TIMESTAMP REPLY]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_IREQ, &flags)          ? "[INFO REQ]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_IREQREPLY, &flags)     ? "[INFO REPLY]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_MASKREQ , &flags)      ? "[MASK REQ]": "",
	   NPROBE_FD_ISSET(NPROBE_ICMP_MASKREPLY, &flags)     ? "[MASK REPLY]": "");
}

/* ****************************************************** */

void 
printFlow(np_ctxt_t *npctxt, HashBucket *theFlow, int direction) 
{
  char buf[256] = {0}, buf1[256] = {0}, latBuf[32] = {0}, *fragmented = "";
  char icmpBuf[128] = {0}, applLatBuf[32] = {0};
  int len, theLen;
  unsigned char *thePayload;

  if(((direction == 0) && fragmentedPacketSrc2Dst(theFlow))
     || ((direction == 1) && fragmentedPacketDst2Src(theFlow)))
    fragmented = " [FRAGMENT]";

  if(nwLatencyComputed(theFlow) && (theFlow->nwLatency > 0)) {
    snprintf(latBuf, sizeof(latBuf), "[N: %.2f ms]",
	     (float)(theFlow->nwLatency / 4294967));
  }

  if(applLatencyComputed(theFlow)) {
    if((direction == 0) && theFlow->src2dstApplLatency)
      snprintf(applLatBuf, sizeof(applLatBuf), "[A: %.2f ms]",
	       (float)(theFlow->src2dstApplLatency / 4294967));
    else if((direction == 1) && theFlow->dst2srcApplLatency)
      snprintf(applLatBuf, sizeof(applLatBuf), "[A: %.2f ms]",
	       (float)(theFlow->dst2srcApplLatency / 4294967));
  }

  if(theFlow->proto == IPPROTO_ICMP) {
    if(direction == 0)
      printICMPflags(theFlow->src2dstIcmpFlags, icmpBuf, sizeof(icmpBuf));
    else
      printICMPflags(theFlow->dst2srcIcmpFlags, icmpBuf, sizeof(icmpBuf));
  }

  if(direction == 0) {
    theLen     = theFlow->src2dstPayloadLen;
    thePayload = theFlow->src2dstPayload;
  } else {
    theLen     = theFlow->dst2srcPayloadLen;
    thePayload = theFlow->dst2srcPayload;
  }

  if(theLen >= npctxt->maxPayloadLen) 
    len = npctxt->maxPayloadLen; 
  else 
    len = theLen;

  if(direction == 0) {
    printf("Emitting: [%s] %s:%d -> %s:%d [%llu pkt/%d bytes] %s %s %s%s\n",
	   proto2name(theFlow->proto), _intoa(theFlow->src, buf, sizeof(buf)), theFlow->sport,
	   _intoa(theFlow->dst, buf1, sizeof(buf1)), theFlow->dport,
	   theFlow->pktSent, (int)theFlow->bytesSent, latBuf, applLatBuf, icmpBuf, fragmented);
    if(theFlow->src2dstFingerprint[0] != '\0')
      printf("Fingeprint: '%s'", theFlow->src2dstFingerprint);
  } else {
    printf("Emitting: [%s] %s:%d -> %s:%d [%llu pkt/%d bytes] %s %s %s%s\n",
	   proto2name(theFlow->proto), _intoa(theFlow->dst, buf, sizeof(buf)), theFlow->dport,
	   _intoa(theFlow->src, buf1, sizeof(buf1)), theFlow->sport,
	   theFlow->pktRcvd, (int)theFlow->bytesRcvd, latBuf, applLatBuf, icmpBuf, fragmented);
    if(theFlow->dst2srcFingerprint[0] != '\0')
      printf("Fingeprint: '%s'", theFlow->dst2srcFingerprint);
  }
}

/* ****************************************************** */

int isFlowExpired(np_ctxt_t *npctxt, HashBucket *myBucket, time_t theTime) {
  /* Treat time differences as unsigned - there is a chance that the timestamping clock is
   * ahead of the PC clock. This would look like a huge time difference with unsigned arithmetic.
   */ 
  if(isCacheBucket(myBucket)) {
    if((signed) (theTime - (myBucket->enteredCache >> 32)) >= npctxt->cacheTimeout) {
      /* expired from cache */
      myBucket->flowEndReason = FLOW_END_CACHE_EXPIRED;
#ifdef DEBUG_JK
      npctxt->endCntCacheExpired++;
#endif
      return 1;
    }
    return 0;
  }
  if((signed) (theTime - (myBucket->lastSeenSent >> 32))  >= npctxt->idleTimeout) {
    /* flow expired: data not sent for a while */
    myBucket->flowEndReason = FLOW_END_IDLE;
#ifdef DEBUG_JK
    npctxt->endCntIdle++;
#endif
    return 1;
  }

  if((signed) (theTime - (myBucket->firstSeenSent >> 32)) >= npctxt->lifetimeTimeout) {
    /* flow expired: flow active but too old   */
    myBucket->flowEndReason = FLOW_END_ACTIVE;
#ifdef DEBUG_JK
      npctxt->endCntActive++;
#endif
    return 1;    
  }
  if(myBucket->pktRcvd > 0) {
    if((signed) (theTime - (myBucket->lastSeenRcvd >> 32)) >= npctxt->idleTimeout) {
      /* flow expired: data not sent for a while */
      myBucket->flowEndReason = FLOW_END_IDLE;
#ifdef DEBUG_JK
      npctxt->endCntIdle++;
#endif
      return 1;
    }
    if((signed) (theTime - (myBucket->firstSeenRcvd >> 32)) >= npctxt->lifetimeTimeout) {
      /* flow expired: flow active but too old   */
      myBucket->flowEndReason = FLOW_END_ACTIVE;
#ifdef DEBUG_JK
      npctxt->endCntActive++;
#endif
      return 1;
    }
  }
  return 0;
  
}

/* ****************************************************** */

void printBucket(HashBucket *myBucket) {
  char str[32], str1[32];
  int a = time(NULL) - (myBucket->firstSeenSent >> 32);
  int b = time(NULL) - (myBucket->lastSeenSent >> 32); 
  int c = myBucket->bytesRcvd ? time(NULL) - (myBucket->firstSeenRcvd >> 32) : 0;
  int d = myBucket->bytesRcvd ? time(NULL) - (myBucket->lastSeenRcvd >> 32) : 0;

#ifdef DEBUG_IPFIX
  if((a > 30) || (b>30) || (c>30) || (d>30))
#endif
    {
      printf("[%4s] %s:%d [%llu pkts] <-> %s:%d [%llu pkts] [FsSent=%d][LsSent=%d][FsRcvd=%d][LsRcvd=%d]\n",
	     proto2name(myBucket->proto),
	     _intoa(myBucket->src, str, sizeof(str)), myBucket->sport, myBucket->pktSent,
	     _intoa(myBucket->dst, str1, sizeof(str1)), myBucket->dport, myBucket->pktRcvd,
	     a, b, c, d);
    }
}

/* ******************************************************** */

void walkHash(np_ctxt_t *npctxt, int flushHash) {
  u_int mutexIdx = npctxt->walkIndex % MAX_HASH_MUTEXES;
  HashBucket *myPrevBucket, *myBucket, *myNextBucket, *cacheBucket;
  time_t now = time(NULL);
  u_int numBucketsExported = 0;

#ifdef DEBUG_EXPORT
  printf("begin walkHash(%d)\n", npctxt->walkIndex);
#endif

  pthread_mutex_lock(&hashMutex[mutexIdx]);
  myPrevBucket = NULL, myBucket = npctxt->hash[npctxt->walkIndex];

  while(myBucket != NULL) {
#ifdef ENABLE_MAGIC
    if(myBucket->magic != 67) {
      printf("Error (2): magic error detected (magic=%d)\n", myBucket->magic);
    }
#endif

    /* FIXME: Shouldn't we compare against simulated time instead? */
    if(flushHash || isFlowExpired(npctxt, myBucket, now)) {
      myNextBucket = myBucket->next;
      cacheBucket = NULL;
      if (myBucket->flowEndReason == FLOW_END_CACHE_EXPIRED) {
#ifdef DEBUG_CACHING
  {
    char buf[256], buf1[256];

    printf("flushing cached flow [%4s] %s:%d -> %s:%d\n",
	   proto2name(myBucket->proto),
	   _intoa(myBucket->src, buf, sizeof(buf)), (int)myBucket->sport,
	   _intoa(myBucket->dst, buf1, sizeof(buf1)), (int)myBucket->dport);
  }
#endif
	/* Recycle bucket, do not export */
	pthread_mutex_lock(&purgedBucketsMutex);
	addToList(myBucket, &npctxt->purgedBuckets);
	npctxt->purgedBucketsLen++;
	pthread_mutex_unlock(&purgedBucketsMutex);
      } else {
	if(flushHash) {
	  myBucket->flowEndReason = FLOW_END_FORCED;
#ifdef DEBUG_JK
	  npctxt->endCntForced++;
#endif
	}

#ifdef DEBUG_EXPORT_2
	printf("Found flow to emit (expired)(idx=%d, reason=%d)\n",
	       npctxt->walkIndex,myBucket->flowEndReason);
#endif

	if(npctxt->bitrateCalcEnabled!=0) {
	  // Force update of the bitrate calculation at the end.
	  updateBitrateCalculation(npctxt, myBucket, 0, 0,0,1);
	  updateBitrateCalculation(npctxt, myBucket, 0, 0,1,1);
	}
	if (myBucket->serviceType == SERVICE_MPEGTS) {
	  if (!is_reasonable_mpegts(myBucket, 0, 1)) {
	    myBucket->serviceType = SERVICE_UNKNOWN;
	  }
	}

	if (!flushHash && flowNeedsCaching(npctxt, myBucket)) {
	  /* FIXME: Shouldn't we use simulated time instead? */
	  cacheBucket = cacheFlow(npctxt, myBucket, now);
	}
	queueBucketToExport(npctxt, myBucket);
	numBucketsExported++;
	if(numBucketsExported >= npctxt->minNumFlowsPerPacket) {
	  signalCondvar(&npctxt->exportQueueCondvar);
	  numBucketsExported=0;
	}
      }
      if(myPrevBucket != NULL) {
	myPrevBucket->next = myNextBucket;
      } else {
	npctxt->hash[npctxt->walkIndex] = myNextBucket;
      }
      if (cacheBucket) {
	addToList(cacheBucket, &npctxt->hash[npctxt->walkIndex]);
	if (myPrevBucket == NULL)
	  myPrevBucket = cacheBucket;
      }
      myBucket = myNextBucket;
    } else {
      /* Move to the next bucket */
      myPrevBucket = myBucket;
      myBucket = myBucket->next;
    }
  } /* while */

  if(numBucketsExported > 0) {
    signalCondvar(&npctxt->exportQueueCondvar);
  }

  pthread_mutex_unlock(&hashMutex[mutexIdx]);

  npctxt->walkIndex = (npctxt->walkIndex + 1) % npctxt->hashSize;

#ifdef DEBUG_EXPORT
  printf("end walkHash(%d)\n", npctxt->walkIndex);
#endif
}

