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
 * history:
 *  2005-06-13 haavardm: Added packet size histogram field, and min/max pktsize
 *
 *
 */

#ifndef __NPROBE_BUCKET__
#define __NPROBE_BUCKET__

/* ********************************** */

#define ENABLE_MAGIC

/* ********************************** */

#define NPROBE_FD_SET(n, p)   (*(p) |= (1 << (n)))
#define NPROBE_FD_CLR(n, p)   (*(p) &= ~(1 << (n)))
#define NPROBE_FD_ISSET(n, p) (*(p) & (1 << (n)))
#define NPROBE_FD_ZERO(p)     (*(p) = 0)


#define FINGERPRINT_LEN          20
#define MAX_PAYLOAD_LEN          1400 /* bytes */

#define FLAG_NW_LATENCY_COMPUTED           1
#define FLAG_APPL_LATENCY_COMPUTED         2
#define FLAG_FRAGMENTED_PACKET_SRC2DST     3
#define FLAG_FRAGMENTED_PACKET_DST2SRC     4
#define FLAG_CACHE_BUCKET                  5

/* Packet size histogram generation */
#define PKTSZ_HISTOGRAM_SLOTS             9
#define PKTDIST_HISTOGRAM_SLOTS           10

/* 
 * Number of intervals when calculating bitrate averages 
 * When changing this, also consider engine.c:updateBitrateCalculation. 
 */
#define BITRATE_AVERAGER_SLOTS            10
#define BITRATE_COUNT                      4
#define BITRATE_1SEC                       0
#define BITRATE_100MS                      1
#define BITRATE_10MS                       2
#define BITRATE_1MS                        3


#define FLOW_END_IDLE      0x01 /* Flow exported due to idle */
#define FLOW_END_ACTIVE    0x02 /* Flow exported due to lifetime max */
#define FLOW_END_EOF       0x03 /* End of flow detected (FIN, ...) */
#define FLOW_END_FORCED    0x04 /* Forced end of flow */
#define FLOW_END_CACHEFULL 0x05 /* Cache was full */
#define FLOW_END_CACHE_EXPIRED 0x06 /* Cache lifetime expired */

#define SERVICE_UNKNOWN 0
#define SERVICE_TORRENT 2
#define SERVICE_SIP     3
#define SERVICE_RTP     4
#define SERVICE_MPEGTS	5

#define SIP_RTP_UNKNOWN  0
#define SIP_RTP_A_KNOWN  1
#define SIP_RTP_AB_KNOWN 2

#define nwLatencyComputed(a)          (NPROBE_FD_ISSET(FLAG_NW_LATENCY_COMPUTED,       &(a->flags)))
#define applLatencyComputed(a)        (NPROBE_FD_ISSET(FLAG_APPL_LATENCY_COMPUTED,     &(a->flags)))
#define fragmentedPacketSrc2Dst(a)    (NPROBE_FD_ISSET(FLAG_FRAGMENTED_PACKET_SRC2DST, &(a->flags)))
#define fragmentedPacketDst2Src(a)    (NPROBE_FD_ISSET(FLAG_FRAGMENTED_PACKET_DST2SRC, &(a->flags)))
#define isCacheBucket(a)              (NPROBE_FD_ISSET(FLAG_CACHE_BUCKET, &(a->flags)))

#ifndef s6_addr32
#ifdef linux
#define s6_addr32 in6_u.u6_addr32
#else
#define s6_addr32 __u6_addr.__u6_addr32
#endif
#endif

#include <search.h>

typedef struct ipAddress {
  u_int8_t ipVersion; /* Either 4 or 6 */
  
  union {
    struct in6_addr ipv6;
    u_int32_t ipv4;
  } ipType;
} IpAddress;

typedef struct {
  int       rtp_initialized;
  u_int32_t rtp_timestamp;
  unsigned long long mapi_timestamp;
  double est_jitter;
  int    njitter;
  double sum_jitter;
  double sqsum_jitter;
  double min_jitter;
  double max_jitter;
} rtp_stat_t;

/* flow stats */
typedef struct {
	int pcr_init;
	u_int64_t total_packets;
	double pcr_last;
	double pcr_jitter_mean;
	double pcr_jitter_sum;
	double pcr_jitter_squared;
	double pcr_jitter_stdv;
	double pcr_num;

#if 0
	int dwell_init;
	int dwell_num;
	double dwell_sum;
	double dwell_squared;
	double dwell_stdv;
	double dwell_mean;

	double last_dwell;
#endif
	
	u_int32_t disconts;
	u_int64_t sync_fail_cnt;
	u_int64_t payload_present_cnt;

	double local_clock;
	double last_realtime;
	
	unsigned long long last_pcr_jitter_update_time;

	/* hash table for continuity checking */
	//struct hsearch_data cc;
	unsigned short cc[8192];   //sorry.

} mpegts_stat_t;


typedef enum {RTP_SNIFF_NOT_STARTED, NOT_RTP, MAYBE_RTP} rtp_sniff_t;

typedef struct hashBucket {
#ifdef ENABLE_MAGIC
  u_char magic;
#endif
  u_short proto;          /* protocol (e.g. UDP/TCP..) */
  IpAddress src;
  u_short sport;
  IpAddress dst;
  u_short dport;
  u_char src2dstTos, dst2srcTos;
  u_int16_t vlanId;
  unsigned short src2dstTcpFlags, dst2srcTcpFlags;
  unsigned short src2dstTcpFlagsFirst, dst2srcTcpFlagsFirst;
  u_short ifindex;		/* Ingress interface of first activity */
  u_char src2dstFingerprint[FINGERPRINT_LEN], dst2srcFingerprint[FINGERPRINT_LEN];
  /* **************** */
  u_long bytesSent;
  unsigned long long firstSeenSent, lastSeenSent;
  u_long bytesRcvd;
  unsigned long long firstSeenRcvd, lastSeenRcvd;
  unsigned long long enteredCache;

  u_int64_t pktSent, pktRcvd;

  struct hashBucket *next;
  u_char src2dstPayloadLen;   /* # of bytes stored on the payload */
  unsigned char *src2dstPayload;
  u_char dst2srcPayloadLen;   /* # of bytes stored on the payload */
  unsigned char *dst2srcPayload;
  u_int32_t flags;               /* bitmask (internal) */
  unsigned long long nwLatency;   /* network Latency (3-way handshake) */
  unsigned long long src2dstApplLatency, dst2srcApplLatency; /* Application Latency */
  u_int32_t src2dstIcmpFlags, dst2srcIcmpFlags;  /* ICMP bitmask */

  u_int32_t src2dstPktSizeHistogram[PKTSZ_HISTOGRAM_SLOTS];
  u_int32_t src2dstPktDistHistogram[PKTDIST_HISTOGRAM_SLOTS];
  u_int32_t dst2srcPktSizeHistogram[PKTSZ_HISTOGRAM_SLOTS];
  u_int32_t dst2srcPktDistHistogram[PKTDIST_HISTOGRAM_SLOTS];

  u_int16_t src2dstMinPktSize, dst2srcMinPktSize;
  u_int16_t src2dstMaxPktSize, dst2srcMaxPktSize;

  u_int32_t src2dstBitrateAverager[BITRATE_COUNT][BITRATE_AVERAGER_SLOTS];
  unsigned long long src2dstBitrateLastUpdate[BITRATE_COUNT];
  u_int32_t dst2srcBitrateAverager[BITRATE_COUNT][BITRATE_AVERAGER_SLOTS];
  unsigned long long dst2srcBitrateLastUpdate[BITRATE_COUNT];

  u_int32_t src2dstRateMax[BITRATE_COUNT],  dst2srcRateMax[BITRATE_COUNT];
  u_int32_t src2dstRateMin[BITRATE_COUNT],  dst2srcRateMin[BITRATE_COUNT];
  u_int16_t src2dstBitrateAveragerPos[BITRATE_COUNT], dst2srcBitrateAveragerPos[BITRATE_COUNT];

  u_int16_t src2dstPktlenIpv4; // ipv4 total length
  u_int16_t dst2srcPktlenIpv4; // ipv4 total length
  u_int32_t src2dstPayloadlenIpv6;
  u_int32_t dst2srcPayloadlenIpv6;

  u_int8_t headerlengthIPv4;

  u_int32_t optionsIPV6src2dst;
  u_int32_t optionsIPV6dst2src;
  u_int64_t optionsIPV4src2dst;
  u_int64_t optionsIPV4dst2src;

  u_int64_t src2dstTcpOpt, dst2srcTcpOpt;

  u_int32_t src2dstflowid; /* ID of flow locally unique to _exporter_. */
  u_int32_t dst2srcflowid;

  u_int8_t flowEndReason;

  u_int64_t src2dstOctetDeltaCount;
  u_int64_t dst2srcOctetDeltaCount;
  /*u_int64_t src2dstOctetTotalCount;
    u_int64_t dst2srcOctetTotalCount;*/

  /* The following used to calculate E(X) and E(X2) for pkt dist and length */
  u_int64_t src2dst_expval_pktdist_x;
  u_int64_t src2dst_expval_pktdist_x2;
  u_int64_t src2dst_expval_pktlength_x;
  u_int64_t src2dst_expval_pktlength_x2;
  u_int64_t dst2src_expval_pktdist_x;
  u_int64_t dst2src_expval_pktdist_x2;
  u_int64_t dst2src_expval_pktlength_x;
  u_int64_t dst2src_expval_pktlength_x2;

  /* The time which the bucket was put in export queue, time() value */
  u_int32_t time_exported;

  u_char src2dstMinTTL;
  u_char src2dstMaxTTL;
  u_char dst2srcMinTTL;
  u_char dst2srcMaxTTL;
  
  u_int32_t src2dst_last_sequence_number;
  u_int32_t src2dst_num_packets_out_of_sequence;
  u_int32_t dst2src_last_sequence_number;
  u_int32_t dst2src_num_packets_out_of_sequence;

  u_int16_t serviceType;

  char *sip_call_id;
  u_int8_t  sip_rtp_status;
  IpAddress sip_rtp_a_addr;
  u_short   sip_rtp_a_port;

  u_int32_t rtcp_jitter;   /* Statistical variance of interarrival time (ts) */
  u_int8_t  rtcp_lostfrac; /* Fraction of lost packages (lost/expected*256) */
  u_int32_t rtcp_lostpkts; /* Number of lost packets in the RTP stream */
  u_int16_t rtcp_cycles;   /* Number of cycles in the RTCP int16 seq number */

  rtp_sniff_t  rtp_sniff_res; /* Result of RTP sniffing */
  u_int32_t rtp_last_sequence_number;
  u_int32_t timestamp;
  u_int32_t rtp_sync_source;
  u_int32_t rtp_sequence_badness;
  
  rtp_stat_t *rtp_a_stat;
  rtp_stat_t *rtp_b_stat;

  mpegts_stat_t *mpegts_stat;

  u_int8_t pim_count;

  u_int16_t src2dstTcpWindowSize;
  u_int16_t dst2srcTcpWindowSize;

  u_int32_t src2dstTcpWindowMax, dst2srcTcpWindowMax;
  u_int32_t src2dstTcpWindowMin, dst2srcTcpWindowMin;

  u_char src2dstTcpWindowScale;
  u_char dst2srcTcpWindowScale;

  u_int32_t src2dstTcpwin_eff;          /* Effective TCP transfer window    */
  u_int32_t src2dstTcpwin_eff_seqnum;   /* Last observed sequence num, or 0 */
  u_int32_t src2dstTcpwin_eff_bytes;    /* Number of bytes passed after seqnum */

  u_int32_t dst2srcTcpwin_eff;
  u_int32_t dst2srcTcpwin_eff_seqnum;
  u_int32_t dst2srcTcpwin_eff_bytes;

} HashBucket;

#endif
