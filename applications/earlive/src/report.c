#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "ear/ear.h"
#include "ear/timer.h"
#include "ear/welchia.h"

#include "hex.h"
#include "report.h"

#define int_ntoa(x)	 inet_ntoa(*((struct in_addr *)&x))

char *flow2string(struct hdr addr);
static char *timeval_str(struct timeval *tv);
static struct timeval *relative_time(struct timeval *tv1, struct timeval *tv2);
static void print_result(struct ear *ear, struct ear_alert *result);
static void print_instances(struct ear *ear, struct cache_entry *entry);

// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1:1024->10.0.0.2:23
char *flow2string(struct hdr addr)
{
	static char buf[256];
	strcpy(buf, int_ntoa(addr.saddr));
	sprintf(buf + strlen(buf), ":%i -> ", addr.source);
	strcat(buf, int_ntoa(addr.daddr));
	sprintf(buf + strlen(buf), ":%i", addr.dest);
	return buf;
}

static char *timeval_str(struct timeval *tv)
{
	static char result[80];
	snprintf(result, sizeof result, "%lu.%.6lu",
			(int) tv->tv_sec, (int) tv->tv_usec);
	return result;
}

static struct timeval *relative_time(struct timeval *tv1, struct timeval *tv2)
{
	static struct timeval result;
	xtimersub(tv2, tv1, &result);
	return &result;
}

static void print_result(struct ear *ear, struct ear_alert *result)
{
	
	printf("0x%.8x %s", result->hash, timeval_str(&CURRENT_TIME));
	printf(" %s \n",
		(result->positive == TRUE_POSITIVE) ? "true" : "false");
	hex_print(result->data, result->dsize, "");
	printf("\n");
}


static void print_instances(struct ear *ear, struct cache_entry *entry)
{
	int i;
	for (i = 0; i < entry->count; i++) {
		printf("%s", int_ntoa(entry->dest->src[i]));
		printf(":%d",entry->dest->sp[i]);
		printf(" -> %s", int_ntoa(entry->dest->dst[i]));
		printf(":%d", entry->dest->dp[i]);
		printf(" offset: ");
		printf("%u", entry->dest->offset[i]);
		printf(" timestamp: ");
		printf("%s", timeval_str(&entry->dest->ts[i]));
		printf("\n");
	}
}

void report_alert(struct ear *ear, struct ear_alert *result, struct cache_entry *cache_entry)
{
    printf("ALERT\n");
    print_result(ear, result);
    print_instances(ear, cache_entry);
    printf("\n:ALERT\n");
    fflush(stdout);

}

void report_tracked(struct ear *ear, uint32_t hash, int offset, struct hdr flow)
{
	printf("TRACKED\n");
	printf("0x%.8x %d %s %s\n\n", hash, offset,
			timeval_str(&CURRENT_TIME), flow2string(flow));

}

//not called by ear
void report_attack(struct ear *ear, struct hdr *addr)
{
	static struct timeval last_welchia_attack;

	struct timeval tv;
	ear->attacks++;
	xtimersub(&CURRENT_TIME, &last_welchia_attack, &tv);
	printf("ear: welchia attack from %s ",
		int_ntoa(addr->saddr));
	printf("to %s ",
		int_ntoa(addr->daddr));
	printf("at %s ",
		timeval_str(relative_time(&ear->tstart, &CURRENT_TIME)));
	printf("%s since last attack\n", timeval_str(&tv));
	last_welchia_attack = CURRENT_TIME;
}


void report_stats(struct ear *ear, struct ear_stats *stats)
{
	printf("STATUS\n");
	printf("timestamp: %s\n", timeval_str(stats->timestamp));
	printf("elapsed_wallclock_time: %s\n",
		timeval_str(&stats->elapsed_wallclock_time));
	printf("elapsed_cpu_time: %.2f\n", stats->elapsed_cpu_time);
	printf("bytes_processed: %llu\n", stats->bytes_processed);
	printf("similarity: %d\n", stats->similarity); //added
	printf("max_usage: %d\n", ear->max_usage);
	printf("avg_usage: %f\n", stats->avg_usage);
	printf("cur_usage: %d\n", stats->cur_usage);
	printf("hash_lookups: %d\n", stats->hash_lookups);
	printf("hash_probes: %d\n", stats->hash_probes);
	printf("avg_hash_access: %f\n", stats->avg_hash_access);
	printf("avg_hash_collision: %f\n", stats->avg_hash_collision);
	printf("\n:STATUS\n");
	fflush(stdout);
}


void report_summary(struct ear *ear, struct ear_stats *stats)
{
	printf("SUMMARY\n");
	printf("trace_start: %d (%s)",
		(int) ear->tstart.tv_sec, ctime((time_t *) &ear->tstart.tv_sec));
	printf("trace_stop: %d (%s)",
		(int) ear->tstop.tv_sec, ctime((time_t *) &ear->tstop.tv_sec));

	printf("timestamp: %s\n", timeval_str(stats->timestamp));
	printf("elapsed_wallclock_time: %s\n",
		timeval_str(&stats->elapsed_wallclock_time));
	printf("elapsed_cpu_time: %.2f\n", stats->elapsed_cpu_time);
	printf("bytes_processed: %lld\n", stats->bytes_processed);
	printf("max_usage: %d\n", ear->max_usage);
	printf("avg_usage: %f\n", stats->avg_usage);
	printf("cur_usage: %d\n", stats->cur_usage);
	printf("hash_lookups: %d\n", stats->hash_lookups);
	printf("hash_probes: %d\n", stats->hash_probes);
	printf("avg_hash_access: %f\n", stats->avg_hash_access);
	printf("avg_hash_collision: %f\n", stats->avg_hash_collision);
	printf("stream_limit: %d\n", ear->stream_limit);
	printf("sampling_mask: 0x%.8x\n", ear->sampling_mask);
	printf("string_length: %d\n", ear->span);
	printf("queue_size: %d\n", ear->cache->queue_size);
	printf("hashtable_capacity: %d\n", ear->cache->capacity);
	printf("threshold: %d\n", ear->cache->threshold);
	printf("detection_delay: %d\n", ear->detection_delay);
	printf("attacks: %d\n", ear->attacks);
	printf("\n");
}

void report_sled(struct hdr addr)
{
	printf("SLED\n");
	printf("%s\n", timeval_str(&CURRENT_TIME));
	printf("%s:%d -> ", int_ntoa(addr.saddr), addr.source);
	printf("%s:%d", int_ntoa(addr.daddr), addr.dest);
	printf("\n");
	printf("\n");
}
