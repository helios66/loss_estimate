#ifndef CACHE_H
#define CACHE_H

#include <stdlib.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "config.h"

#define MAX_DST		20

// Slot is empty
#define CACHE_EMPTY			1
// Substring has multiple destinations stored in allocated table
#define CACHE_MULTIPLE_DST	2
// Substring should be tracked
#define CACHE_TRACK			4
// Substring should be ignored
#define CACHE_IGNORE		8
// Substring should not be evicted
#define CACHE_PIN			16


// cached substring
struct cache_entry {
	u_int32_t key; // payload fingerprint
	struct timeval expire;

	//struct ear_result *result; // TODO replace this with lookup
	int flags;
	int count;
	int synonym_count;
	// Single destination
	// TODO store in union with multiple destinations pointer
	// (they are not used simultaneously)
	u_int dst;
	u_int src;
	u_short sp;
	u_short dp;
	int offset;
	struct timeval ts;
	struct cache_dest *dest;
};

// multiple destinations
struct cache_dest {
	u_int dst[MAX_DST];
	u_int src[MAX_DST];
	u_short dp[MAX_DST];
	u_short sp[MAX_DST];
	int offset[MAX_DST];
	struct timeval ts[MAX_DST];
};

// substring cache
struct cache {
	int threshold; // threshold on number of distinct destinations

	int mask;
	int capacity;
	u_int32_t queue_size;
	struct timeval queue_size_tv;
	int usage;
	unsigned int tmp_sim;
	//u_int32_t epoch;
	struct cache_entry *table;

	// hashtable statistics
	u_int32_t hash_lookups;
	u_int32_t hash_probes;
	u_int32_t hash_collisions;
};
//
// create a cache queue of given capacity in msec
struct cache *cache_create(int capacity, int threshold);

// destroy a cache queue
void cache_destroy(struct cache *cache);

// memory usage and similarity
void cache_stats(struct cache *cache, int *usage, unsigned int *similarity);
struct cache_entry *cache_entry_create(struct cache *cache, u_int32_t hash);

// lookup cache entry by payload fingerprint,
struct cache_entry *cache_entry_lookup(struct cache *cache, u_int32_t hash);

// keep remembering entry
void cache_touch(struct cache *cache, struct cache_entry *cache_entry);

// check whether destination has been encountered
int is_seen(struct cache_entry *cache_entry, u_int dst);

#endif
