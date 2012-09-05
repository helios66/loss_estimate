#ifndef EAR_H
#define EAR_H

#include <sys/time.h>
#include <netinet/in.h>

#include "cache.h"
#include "rabin.h"

#define LOG(s, ...);	do { printf("LOG: "s" [%s:%d]\n", \
			## __VA_ARGS__, __FILE__, __LINE__); \
			fflush(stdout); } while (0);



struct hdr {
	unsigned short source,dest; // client and server port numbers
	unsigned long saddr,daddr;  // client and server IP addresses
};

struct ear_alert {
	uint32_t hash;
	u_char *data;
	int dsize;
	int positive;
};

struct ear_stats {
	struct timeval *timestamp;
	struct timeval elapsed_wallclock_time;
	double elapsed_cpu_time;
	unsigned long long bytes_processed;

	int max_usage;
	float avg_usage;
	int cur_usage;
	unsigned int similarity;

	int hash_lookups;
	int hash_probes;
	float avg_hash_access;
	float avg_hash_collision;
};

struct ear {
	int span;
	int stream_limit;
	int sampling_mask;
	int skip_nul;
	struct cache *cache;
	struct rabin *rabin;
	// statistics
	int cache_resets;
	unsigned long long bytes_processed;
	int monitored;
	struct timeval tstart;
	struct timeval tstop;
	double t0;
	int attacks;
	int detection_delay;

	int cur_usage;
	int max_usage;
	int usage_samples;
	int usage_sum;
	
	//check params change
	void (*param_change)(struct ear *ear);

	// reporting
	void (*report_alert)(struct ear *ear, struct ear_alert *result,
			struct cache_entry *cache_entry);
	void (*report_tracked)(struct ear *ear, uint32_t hash, int offset, struct hdr flow);
	void (*report_attack)(struct ear *ear, struct hdr *t);
	void (*report_stats)(struct ear *ear, struct ear_stats *stats);
	void (*report_summary)(struct ear *ear, struct ear_stats *stats);
};

struct ear_flow_state {
	u_int32_t hash;
	int nonzero_bytes;
};

struct ear *ear_create(int span, int capacity, int dst_threshold,
		int stream_limit, uint32_t sampling_mask, int skip_nul);
void ear_process(struct ear *ear, struct hdr *t, unsigned char *data,
		int dsize, int offset, struct ear_flow_state *ear_flow_state);
void ear_destroy(struct ear *ear);
struct ear_flow_state *ear_flow_state_create(void);
void ear_flow_state_destroy(struct ear_flow_state *);

#endif
