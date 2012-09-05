/* lykkebo, july 2009
/	 * 08072009: start
 */
#include <mapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "mpegts.h"
#include "debug.h"
#include <math.h>
//#include "engine.h"

#include "npctxt.h"

//#include "nprobe_bucket.h"
#include <search.h>


static void parse_mpegts (const char* pkt, HashBucket *bkt, unsigned long long stamp, int direction);
static void parse_mts_adaptation(const char* apt, mpegts_fields* h,  HashBucket *bkt, unsigned long long stamp);
static void update_pcr_stats(mpegts_fields* h,  HashBucket* bkt, unsigned long long stamp);
#if 0
static void parse_mts_payload(const char* pld, mpegts_fields* h, HashBucket *bkt);
static void update_pts_stats(mpegts_fields* h, HashBucket* bkt);
static u_int64_t extract_pts (const char *bytes);
#endif
static void check_cc(mpegts_fields* h, HashBucket* bkt);
static void update_local_clock(HashBucket* bkt, unsigned long long stamp);
static inline double clock_to_seconds(unsigned long long ticks, int Hz);
static int is_outlier(double sample, double mean, double stdv);

/* Check if this UDP-packet contains MPEG-TS data. 
		It's pretty likely that a pattern of
		([0x47] [187 bytes]_1 [0x47] [187 bytes]_2 ..., []_7)
		is a transport stream
*/

int is_mpegts (const char* pkt, unsigned int le)
{
	int i = 0,n = 0, p = 0;  //-8 ?? 
	
	if(le <= 0) { return -1; }
	if(pkt == NULL) { return -1; }
	/* We need 3 MPEG packets for reliable classification */
	if(le < 564) { return -1; }

	n = le / MPEGTS_PACKET_SIZE;
	p = MPEGTS_PACKET_SIZE;

	//Check if we have repeating 0x47-pattern (0x47 for every pth bytes).
	while (i < n) {
		if (pkt[p*i] != 0x47)
			return -1;
		i++;	
	}	
	DEBUG_CMD(printf("MPEG-TS stream found with high probability!\n"));
	
	return 1;
}


/* Takes an MPEG-TS-packet, parses the header fields into
the structure mpegts_fields and attempts to :
 * Parse the adaptation field (if present)
 * Check if we have continuity errors (by checking the CC-header field)
 * Extract PTS from the PES-header

*/
static void
parse_mpegts (const char* pkt, HashBucket* bkt, unsigned long long stamp, int direction)
{

	mpegts_stat_t *s = bkt->mpegts_stat;

	//More null-cheks, but these should never happen...
	if(pkt == NULL) {
		goto end;
	}

	update_local_clock(bkt, stamp);
	s->total_packets++;
	
	/* Dig out header fields, parse them */
	u_int16_t pid;
	unsigned char sync;
	mpegts_fields h;
	sync = pkt[0];
	if(sync != 0x47) { 
		s->sync_fail_cnt++;
		goto end;
	}
	memset(&h, 0, sizeof h);
	memcpy(&pid, pkt + 1, 2);
	
	if (sync != 0x47) {
		DEBUG_CMD(printf("Attempted to parse non-mpegts packet\n"));
	}

	h.PID = ntohs(pid) & 0x1FFF;
	h.cc = pkt[3] & 0x0F;
	h.transport_error = pkt[1] & 0x80;
	h.adaptation_present = (pkt[3] >> 5) & 0x01;
	h.payload_present = (pkt[3] >> 4) & 0x01;
	unsigned char adapt_length = 0;
	s->payload_present_cnt += h.payload_present ? 1 : 0;
	
	if (h.adaptation_present == 1) {
		adapt_length = pkt[4];
		parse_mts_adaptation(&pkt[4], &h, bkt, stamp);
	}
	
	/* Inspect the continuity fields */
	check_cc(&h, bkt);

#if 0
	if(s->pcr_init == 1) {
		/* Dwell time only makes sense if we have seeded 
		our local clock */

		if (h.payload_present == 1) {
			parse_mts_payload(pkt + 4 + adapt_length, &h, bkt);
		}
	}
#endif
end:
	if (!is_reasonable_mpegts(bkt, direction, 0)) {
		bkt->serviceType = SERVICE_UNKNOWN;
	}
}

int
is_reasonable_mpegts(HashBucket *bkt, int direction, int at_end)
{
	int res = 1;
	mpegts_stat_t *s;
	u_int64_t sync_ok_cnt;
	u_int64_t payload_missing_cnt;
	u_int64_t ip_pkt_cnt;

	if (!bkt || !bkt->mpegts_stat) {
		return 0;
	}
	 
	s = bkt->mpegts_stat;
	sync_ok_cnt = s->total_packets - s->sync_fail_cnt;
	payload_missing_cnt = s->total_packets - s->payload_present_cnt;
	ip_pkt_cnt = bkt->pktSent;
	if ((at_end && bkt->pktRcvd > ip_pkt_cnt) ||
	    (!at_end && direction == 1)) {
		ip_pkt_cnt = bkt->pktRcvd;
	}

	/* Reject if > 1/3 of pkts are sync failures, > 1/3 of pkts lack payload or
	 * fewer MPEG packets than IP packets. */
	if (at_end || s->total_packets > 100 || ip_pkt_cnt > 100) {
		if ((3 * s->sync_fail_cnt > sync_ok_cnt) ||
		    (3 * payload_missing_cnt > s->total_packets) ||
		    (s->total_packets < ip_pkt_cnt)) {
			res = 0;
		}
	}
	return res;
}

double double_time(unsigned long long stamp)
{
		return stamp / 4294967296.;
}


/* This takes a bucket and updates the counter that maintains the local PCR,
used for decoding (only we're not decoding, but we could've) */
static void
update_local_clock(HashBucket* bkt, unsigned long long stamp) 
{
	if(bkt->mpegts_stat->pcr_init != 1) 
	  return;

	double now = double_time(stamp);
	double diff = now -  bkt->mpegts_stat->last_realtime;
	bkt->mpegts_stat->last_realtime = now;
	bkt->mpegts_stat->local_clock += diff;
}



/* Parses the adaptation field of an MPEG-TS packet */
static void
parse_mts_adaptation (const char* apt, mpegts_fields* h, HashBucket *bkt, unsigned long long stamp)
{	
	/* Find the PCR field if present */
	unsigned int len = apt[0];
	unsigned char pcr_present = 0;

	if (len >= 1) {
		h->discontinuity = (apt[1] >> 7) & 0x01;
	}
	if (len >= 7) {
		pcr_present = (apt[1] >> 4) & 0x01;
	}
	if (pcr_present == 1) {
		unsigned int temp;
		memcpy(&temp, &apt[2], 4);
		h->PCR_base = (u_int64_t) ntohl(temp) << 1;
		h->PCR_base |= (unsigned char)apt[6] >> 7;
	//	h->num_pcr++;
		update_pcr_stats(h, bkt, stamp);
	} else {
		h->PCR_base = 0;
	}
}



#if 0
/* pld is an MPEG-TS payload; usually a PES packet */
static void
parse_mts_payload (const char* pld, mpegts_fields* h, HashBucket *bkt)
{
	/* this test isn't completly correct, but byte-order is wonky stuff. */
	unsigned short check = 0, len = 0;
	memcpy(&check, pld+1, 2);
	check = ntohs(check);
	if (check != 0x0001) {
		return;
	}

	memcpy(&len, &pld[4], 2);
	memcpy(&h->stream_id, pld+3, 1);

	int pts_present = (*(pld+7) >> 7) & 0x01;
	if (pts_present == 1) {
		h->PTS = extract_pts(pld + 9);
		update_pts_stats(h,bkt);
	}
	
}

/* Extract PTS from the payload of an PES-packet,
	discard least significant bit and return approximation (+- 1) 
	
	NOTE: This will go horribly wrong if MSB != 0... 
	*/
static u_int64_t
extract_pts (const char *bytes) 
{
		unsigned char test = *bytes >> 4;
		u_int64_t pts;

		if (test != 2 && test != 3) {
			DEBUG_CMD(printf("Attempted to extract PTS field with invalid first bits\n"));
		}
		/* PTS FIELD LAYOUT:
		MSB						LSB
		[4] [3] [1] [15] [1] [15] [1]
		| b1      | | b23  | | b45  |
		The [1]'s are marker bits, and should be 1. I don't bother testing.
		*/
		u_int32_t b1 = 0;
		u_int32_t b2 = 0;
		u_int32_t b3 = 0;
		u_int32_t b4 = 0;
		u_int32_t b5 = 0;
		u_int32_t bit_last = 0;

		//printf("%x\n", bytes[0]);
		memcpy(&b1, bytes, 		1);  // [b1] [23 bit]
		memcpy(&b2, bytes +1, 1);  // [b23] [16 bit]
		memcpy(&b3, bytes +2, 1);  // [b23] [16 bit]
		memcpy(&b4, bytes +3, 1);  // [b23] [16 bit]
		memcpy(&b5, bytes +4, 1);  // [b23] [16 bit]

		bit_last = (b5 >> 1) & 1;
		b1 = (b1 & 0x0000000E) << 28 	; //[aaa00000000...]
		b2 = (b2 & 0x000000FF) << 21;
		b3 = ((b3 ) & 0x000000FE) << 13;
		b4 = ((b4 ) & 0x000000FF) << 6;
		b5 = ((b5 ) & 0x000000FE) >> 2;

		pts = ((u_int64_t)(b1|b2|b3|b4|b5) << 1);
		pts |= bit_last;
		return pts;
}
#endif

/* Assumes (somewhat weakly) mpeg packets are of constant size, chops the UDP packet
into equal parts and sends each packet to parse / stat-update */
void split_parse_mpegts(const char* pkt, unsigned int len, struct hashBucket* bkt,
			unsigned long long stamp, int direction)
{
	if(pkt == NULL || len < MPEGTS_WORK_THRESHOLD * MPEGTS_PACKET_SIZE) {
		return;
	}

	int n = len / MPEGTS_PACKET_SIZE, i=0;

	for(i=0; i < n && bkt->serviceType == SERVICE_MPEGTS; i++){
		parse_mpegts(&pkt[i*MPEGTS_PACKET_SIZE], bkt, stamp, direction);
	}
}

#if 0
static void 
print_mts_fields(mpegts_fields* h)
{
	printf("PID:%hx CC:%hu TrErr: %x PCR_base: %llx\n PTS: %x\n",
					h->PID, h->cc, h->transport_error, h->PCR_base, h->PTS); 	
}
#endif


/* Update PCR stats takes the (already parsed) header structure h,
		and updates the supplied bucket with data from this packet */
static void 
update_pcr_stats(mpegts_fields* h, HashBucket* bkt, unsigned long long stamp)
{
	mpegts_stat_t* s = bkt->mpegts_stat;
	
	double 	decode_difference, 
					pcr_current,
					encode_difference,
					jitter_sample,
					squared_jitter_sample,
					sum,
					sum_2,
					stdv,
					mean;

	int			n;  //Current number of packets;

	s->pcr_num++;
	if (s->pcr_init == 1) {
		decode_difference = double_time(stamp - s->last_pcr_jitter_update_time);
		//encode (pcr) time
		pcr_current = clock_to_seconds((h->PCR_base), SYSTEM_CLOCK_HZ);

		encode_difference = fabs(pcr_current - s->pcr_last);

		jitter_sample = fabs (encode_difference - decode_difference);	
		squared_jitter_sample = jitter_sample * jitter_sample;
		
		sum = s->pcr_jitter_sum + jitter_sample;
		sum_2 = s->pcr_jitter_squared + squared_jitter_sample;
		n = s->pcr_num;

		stdv = sqrt (fabs (sum_2 / (double)n - pow (sum / (double)n, 2))); //standard deviation
		mean = sum / (double)n; //arithmetic mean

	//	printf("PCR stdv: %f mean:%f\n", stdv, mean);
		/* I really don't know what causes this, but sometimes we get
				really weird values. let's discard outliers that's over 10 x the standard deviation over the mean or > 10 s */
		if (!is_outlier(jitter_sample, mean, stdv)) {
			s->pcr_jitter_sum = sum;
			s->pcr_jitter_squared = sum_2;
			s->pcr_jitter_stdv = stdv; 		
			s->pcr_jitter_mean = mean;
			/* ad () just the local clock */
			s->local_clock = pcr_current;
		} else {
			//skip this jitter_sample, it's way off, we got a PAT or something.
			s->pcr_num--;	
		}
		
		s->pcr_last = pcr_current;
		s->last_pcr_jitter_update_time = stamp;
	} else {
		DEBUG_CMD(printf("Initializing PCR stats\n"));

		/* Measurement is unintialized. */
		s->pcr_last = (h->PCR_base)/(double)SYSTEM_CLOCK_HZ;
		s->local_clock = s->pcr_last; //seed local clock
		s->pcr_jitter_mean = 0;
		s->pcr_jitter_squared = 0;
		s->pcr_jitter_stdv = 0;
		s->pcr_jitter_sum = 0;
		s->last_pcr_jitter_update_time = stamp;
		s->pcr_init = 1;
	}
}

static int
is_outlier(double sample, double mean, double stdv)
{
	if (fabs(sample) > 10) {
		return 1;
	} else if(fabs(sample) > fabs((10 * stdv) + mean)) { 
		return 1;
	} else {
		return 0;
	}
}

#if 0
static void
update_pts_stats(mpegts_fields* h, HashBucket* bkt)
{
	double pts, dwell_time, squared_dwell_time, dwelltime_sum, dwelltime_sum_2, stdv, mean;
	int n;
	//note:
	mpegts_stat_t* s = bkt->mpegts_stat;

	/* For now, we are only interested in video PES-packets */
	if(h->stream_id != SID_VIDEO) /* But Wikipedia says 224 - 239 are video, 192 - 223 are audio */
		return;

	pts = clock_to_seconds(h->PTS, SYSTEM_CLOCK_HZ);
	s->dwell_num++;
	s->last_dwell = pts;

	dwell_time = fabs(pts - s->local_clock);
	squared_dwell_time = (dwell_time * dwell_time);

	dwelltime_sum = s->dwell_sum + dwell_time;
	dwelltime_sum_2 = s->dwell_squared  + squared_dwell_time;
	n = s->dwell_num;

	stdv = sqrt (fabs (dwelltime_sum_2 / (double)n - pow (dwelltime_sum / (double)n, 2))); //standard deviation
	mean = dwelltime_sum / (double)n; //arithmetic mean

	//printf("PTS stdv:%f mean:%f\n", stdv, mean);
	if (!is_outlier(dwell_time, mean, stdv)) {
		s->dwell_sum = dwelltime_sum;
		s->dwell_squared = dwelltime_sum_2;
		s->dwell_stdv = stdv; 		
		s->dwell_mean = mean;
	} else {
		//skip this dwell_time, it's way off, we got a PAT or something.
		s->dwell_num--;	
	}
}
#endif


static inline double
clock_to_seconds(unsigned long long ticks, int Hz) 
{
	return ticks/(double)Hz;
}


static void
check_cc (mpegts_fields* h, HashBucket* bkt) 
{
	unsigned short prior_cc = bkt->mpegts_stat->cc[h->PID];
	bkt->mpegts_stat->cc[h->PID] = h->cc;

	/* Special case, first time we see this packet. */
	if (prior_cc == 16) {
		return;
	}

	if (h->discontinuity == 1) {
		//printf("disc flag set, skipping\n");
		return; //discontinuity expected, doesn't matter.
	}
	
	if (prior_cc == h->cc && h->payload_present == 0) {
		return; //should not increase
	}

	if ((prior_cc + 1) % 16 == h->cc) {
		return; //is ok
	}
	
	if (prior_cc == h->cc &&
			h->payload_present == 1) {
		return; //we have a duplicate TODO: count dupes, max 2
	}
	DEBUG_CMD(printf("Discontinuity in PID %d! found %d expected %d or %d\n", h->PID, h->cc, prior_cc + 1, prior_cc));
	bkt->mpegts_stat->disconts++;
}
