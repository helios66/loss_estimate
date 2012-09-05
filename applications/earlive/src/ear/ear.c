#include "welchia.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>

#include "ear.h"
#include "cache.h"
#include "rabin.h"
#include "cputime.h"
#include "timer.h"

static inline void process_hash(struct ear *ear, struct hdr *t,
		uint32_t hash, unsigned char *buf, int offset);
static void trigger(struct ear *ear, struct cache_entry *cache_entry,
		struct hdr *t, unsigned char *buf);
static void sample_memory_usage(struct ear *ear, struct ear_stats *stats);
static struct ear_stats *make_stats(struct ear* ear);

static unsigned int dropped_hashes=0;

static void trigger(struct ear *ear, struct cache_entry *cache_entry, struct hdr *t, unsigned char *buf)
{
	struct ear_alert *result = malloc(sizeof(struct ear_alert));
	result->hash = cache_entry->key;
	result->data = malloc(ear->span);
	memcpy(result->data, buf, ear->span);
	result->dsize = ear->span;
	result->positive = is_welchia(result->data, result->dsize);

	ear->report_alert(ear, result, cache_entry);

	cache_entry->flags |= CACHE_PIN;	// will never get evicted
	//cache_entry->flags |= CACHE_TRACK;	// will be tracked
	cache_entry->flags |= CACHE_IGNORE;	// will be ignored
	//cache_entry->result = result;	// TODO save space on cache_entry by
					// using lookup with hash
	ear->monitored++;
	if (ear->detection_delay == 0)
		ear->detection_delay = ear->attacks;

	ear->cache->tmp_sim |= 1<<cache_entry->count;
	//LOG("New Alert Reported");
}


struct ear *ear_create(int span, int queue_size, int threshold,
		int stream_limit, uint32_t sampling_mask, int skip_nul)
{
	struct ear *ear = malloc(sizeof(struct ear));

	ear->span = span;
	ear->stream_limit = stream_limit;
	ear->sampling_mask = sampling_mask;
	ear->cache = cache_create(queue_size, threshold);
	ear->skip_nul = skip_nul;

	ear->cache_resets = 0;
	ear->bytes_processed = 0;

	ear->attacks = 0;
	ear->detection_delay = 0;

	ear->rabin = rabin_create(span);
	ear->monitored = 0;

	ear->max_usage = 0;
	ear->usage_samples = 0;

	ear->t0 = get_cputime();

	// ignore zero string
	cache_entry_create(ear->cache, 0x0)->flags = CACHE_IGNORE|CACHE_PIN;
	
	// track one worm string
	//cache_entry_create(ear->cache, 0x06088865)->flags = CACHE_TRACK|CACHE_PIN;
	LOG("Created ear");
	
	return ear;
}


void ear_destroy(struct ear *ear)
{
	ear->report_summary(ear, make_stats(ear));
	cache_destroy(ear->cache);
	free(ear);
	LOG("EAR destroyed");
}

static struct ear_stats *make_stats(struct ear* ear)
{
	static struct ear_stats stats;

	sample_memory_usage(ear, &stats);

	stats.timestamp = &CURRENT_TIME;
	xtimersub(&CURRENT_TIME, &ear->tstart,
			&stats.elapsed_wallclock_time);
	stats.elapsed_cpu_time = get_cputime() - ear->t0;
	stats.bytes_processed = ear->bytes_processed;
	stats.max_usage = ear->max_usage;
	stats.avg_usage = ear->usage_sum / (float)  ear->usage_samples;
	stats.cur_usage = ear->cur_usage;

	stats.hash_lookups = ear->cache->hash_lookups;
	stats.hash_probes = ear->cache->hash_probes;
	stats.avg_hash_access = (ear->cache->hash_probes /
			(float) ear->cache->hash_lookups);
	stats.avg_hash_collision = (ear->cache->hash_collisions /
			(float) ear->cache->hash_lookups);

	return &stats;
}


static inline void process_hash(struct ear *ear, struct hdr *t, uint32_t hash, unsigned char *buf, int offset)
{
	struct cache *cache = ear->cache;
	struct cache_entry *cache_entry;
	int found;

	// deterministic sampling
	if (hash & ear->sampling_mask) {
		return;
	}

	if ((cache_entry = cache_entry_lookup(cache, hash)) != NULL) {
		found = 1;

		if (cache_entry->flags & CACHE_TRACK)
			ear->report_tracked(ear, hash, offset, *t);

		if (cache_entry->flags & CACHE_IGNORE)
			return;

		if (!is_seen(cache_entry, t->daddr)) {
			// maybe move to cache
			if (!(cache_entry->flags & CACHE_MULTIPLE_DST)) {
				cache_entry->flags |= CACHE_MULTIPLE_DST;
				cache_entry->dest = malloc(sizeof(struct cache_dest));
				cache_entry->dest->dst[0] = cache_entry->dst;
				cache_entry->dest->src[0] = cache_entry->src;
				cache_entry->dest->sp[0] = cache_entry->sp;
				cache_entry->dest->dp[0] = cache_entry->dp;
				cache_entry->dest->offset[0] = cache_entry->offset;
				cache_entry->dest->ts[0] = cache_entry->ts;
			}

			// record new destination and increase count
			cache_entry->dest->dst[cache_entry->count] =
				t->daddr;
			cache_entry->dest->src[cache_entry->count] =
				t->saddr;
			cache_entry->dest->sp[cache_entry->count] =
				t->source;
			cache_entry->dest->dp[cache_entry->count] =
				t->dest;
			cache_entry->dest->offset[cache_entry->count] =
				offset;
			cache_entry->dest->ts[cache_entry->count] =
				CURRENT_TIME;
				
			cache_entry->count++;


			if (cache_entry->count == cache->threshold)
				trigger(ear, cache_entry, t, buf);

			cache_touch(cache, cache_entry);
		}

	} else { // not in cache
		found = 0;
		cache_entry = cache_entry_create(cache, hash);
		
		if (cache_entry == NULL) {//cache is full.... 
			dropped_hashes += 1;
			if (dropped_hashes%100 == 0) {
				LOG("Dropped hashes reached %d.", dropped_hashes);
			}
		}
		/*    int thres = cache->threshold, qs = cache->queue_size;
		    cache_destroy(cache);
		    ear->cache = cache = cache_create(qs, thres);
		    LOG("Cache renewed ok!");
		    ear->cache_resets++;
		    cache_entry = cache_entry_create(cache, hash);
		}*/
		else {
			cache_entry->dst = t->daddr;
			cache_entry->src = t->saddr;
			cache_entry->sp = t->source;
			cache_entry->dp = t->dest;
			cache_entry->offset = offset;
			cache_entry->ts = CURRENT_TIME;
			cache_entry->count++;
		}
	}


#if 0
	// poor man's tracking
	if (cache_entry->key == 0x0113e110) {
		printf("tracker: 0x%.8x  hash=0x%.8x", cache_entry->key, hash);
		printf(" %s", found ? "found" : "created");
		printf(" seen at %s", current_time_str(ear));
		printf(" at offset %u",
				a_tcp->server.count - a_tcp->server.count_new
			+ (ear->rabin->offset - ear->rabin->span_size));
		printf(" expires at %s\n",
			timeval_str(relative_time(ear, &cache_entry->expire)));
		printf("tracker: %s\n", flow2string(a_tcp->addr));
		//hex_print(p->data, p->dsize, "Payload");
		//hex_print(rabin_get_buf(ear->rabin), ear->span, "Substring: ");
		//printf("dsize: %d\n", p->dsize);
		//hex_print(p->data, p->dsize, "Packet: ");
	}
#endif

}

// TODO Could move tcp_stream and offset into ear_flow_state
void ear_process(struct ear *ear, struct hdr *t, unsigned char *data, int dsize, int offset, struct ear_flow_state *ear_flow_state)
{
	int i;
	static int next_tick = 0;

	// Maintain timestamps for start and end of trace.
	if (ear->bytes_processed == 0) {
		ear->tstart = CURRENT_TIME;
	}
	ear->tstop = CURRENT_TIME;

	ear->bytes_processed += (unsigned long long) dsize;

	if (dsize >= ear->span) { // wait till we have enough data
		if (offset == 0) { // at start of flow
			i = 0;
		} else {
			i = ear->span - 1;
		}
		for (; i < dsize; i++) {
			if (data[i] == '\0')
				ear_flow_state->nonzero_bytes = 0;
			else
				ear_flow_state->nonzero_bytes++;
			SHIFT_IN(ear->rabin, ear_flow_state->hash, (u_char) data[i]);
			if (i >= ear->span - 1) {
				unsigned char *buf = data + i - (ear->span - 1);
				if (!ear->skip_nul || ear_flow_state->nonzero_bytes >= ear->span)
					process_hash(ear, t, ear_flow_state->hash, buf, offset + i - (ear->span - 1));
				SHIFT_OUT(ear->rabin, ear_flow_state->hash, (u_char) data[i - (ear->span - 1)]);
			}
		}
	}

	if (CURRENT_TIME.tv_sec > next_tick) {
		next_tick = CURRENT_TIME.tv_sec + 1;
		ear->param_change(ear); //added
		ear->report_stats(ear, make_stats(ear));
	}
}

void sample_memory_usage(struct ear *ear, struct ear_stats *stats)
{
	cache_stats(ear->cache, &stats->cur_usage, &stats->similarity);
	if (ear->cur_usage > ear->max_usage)
		ear->max_usage = ear->cur_usage;
	ear->usage_sum += ear->cur_usage;
	ear->usage_samples++;
}

struct ear_flow_state *ear_flow_state_create(void)
{
	struct ear_flow_state *ear_flow_state = malloc(sizeof(struct ear_flow_state));
	ear_flow_state->hash = 0;
	ear_flow_state->nonzero_bytes = 0;
	return ear_flow_state;
}

void ear_flow_state_destroy(struct ear_flow_state *ear_flow_state)
{
	free(ear_flow_state);
}

