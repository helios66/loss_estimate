#ifndef __MPEGTS_H__
#define __MPEGTS_H__

#include "nprobe_bucket.h"

#define MAX_PIDS 32
/* need hash tables */

#include <search.h>
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h>


#define PID_MAX_SIZE 8192 //2^13

#define SID_VIDEO 0xe0
#define SID_AUDIO 0xc2

#define SYSTEM_CLOCK_HZ 90000
#define MPEGTS_PACKET_SIZE 188
#define MPEGTS_WORK_THRESHOLD 3

/* These are the fields used for per-package analysis. */
typedef struct mpegts_headers_t
{	
	unsigned short PID;
	unsigned short cc;
	int transport_error;
	int discontinuity;
	int adaptation_present;
	int payload_present;
//	int has_pcr;
	u_int64_t PCR_base;
	u_int64_t PTS;
	int num_pcr;
	int stream_id;
} mpegts_fields;


int is_mpegts (const char* pkt, unsigned int le);
int is_reasonable_mpegts(HashBucket *bkt, int direction, int at_end);

void split_parse_mpegts(const char* pkt, unsigned int len,  HashBucket *bkt,
			unsigned long long stamp, int direction);

double double_time(unsigned long long stamp);

#endif
