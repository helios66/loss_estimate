#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include "cache.h"
#include "timer.h"
#include "ear.h"

#define IS_EMPTY(cache_entry) ((cache_entry).flags & CACHE_EMPTY)
#define IS_EMPTY_OR_EXPIRED(cache_entry) (IS_EMPTY(cache_entry) || is_expired(&cache_entry))

static inline int is_expired(struct cache_entry *cache_entry)
{
	return xtimercmp(&cache_entry->expire, &CURRENT_TIME)
		&& !(cache_entry->flags & CACHE_PIN);
}

struct cache_entry *cache_entry_create(struct cache *cache, u_int32_t key)
{
	int i, slot;

	slot = key & cache->mask;
	cache->table[slot].synonym_count++;

	for (i = 0; !IS_EMPTY_OR_EXPIRED(cache->table[slot])
			&& i < cache->capacity; i++) {
		slot = (slot + 1) & cache->mask;
	}

	if (i == cache->capacity) {
		// cache capacity exceeded
		LOG("Cache capacity exceeded");
		return NULL;
	}

	if (!IS_EMPTY(cache->table[slot])) { // is expired
		int primary_slot = cache->table[slot].key & cache->mask;
		cache->table[primary_slot].synonym_count--;
	}

	if (cache->table[slot].flags & CACHE_MULTIPLE_DST) {
		free(cache->table[slot].dest);
	}

	cache->table[slot].key = key;
	cache->table[slot].flags = 0;
	cache->table[slot].count = 0;
	// TODO remove this kludge (if line). 
	// Its for adding ignore entries before reading the trace.
	if (CURRENT_TIME.tv_sec != 0 && CURRENT_TIME.tv_usec != 0)
		xtimeradd(&CURRENT_TIME, &cache->queue_size_tv,
			&cache->table[slot].expire);

	return &cache->table[slot];
}

struct cache_entry *cache_entry_lookup(struct cache *cache, u_int32_t key)
{
	int i;
	int synonym_count;
	int primary_slot;
	int slot;
	struct cache_entry *cache_entry = NULL;

	cache->hash_lookups++;
	
	slot = primary_slot = key & cache->mask;
	synonym_count = cache->table[key & cache->mask].synonym_count;

	//printf("lookup... %.8x (hash %.8x) %d\n", key, primary_slot, synonym_count);
	for (i = 0; i < synonym_count; i++) {
		while ((cache->table[slot].key & cache->mask) != primary_slot) {
			slot = (slot + 1) & cache->mask;
		}

		//printf("check... %.8x\n", cache->table[slot].key);
		if (cache->table[slot].key == key
				&& !is_expired(&cache->table[slot])) {
			cache_entry = &cache->table[slot];
			break;
		}

		slot = (slot + 1) & cache->mask;
	}

	cache->hash_probes += (slot - primary_slot) & cache->mask;
	cache->hash_collisions += synonym_count;
	
	return cache_entry;
}

void cache_touch(struct cache *cache, struct cache_entry *cache_entry)
{
	
	//timeradd(&cache_entry->expire, &cache->queue_size_tv, &cache_entry->expire);
	
	xtimeradd(&CURRENT_TIME, &cache->queue_size_tv, &cache_entry->expire);
}

struct cache *cache_create(int queue_size, int threshold)
{
	int i;
	struct cache *cache = malloc(sizeof(struct cache));
	cache->mask = 0x3ffff; // 256K
	cache->queue_size = queue_size;
	// queue_size is in milliseconds
	cache->queue_size_tv.tv_sec = queue_size / 1000;
	cache->queue_size_tv.tv_usec = (queue_size % 1000) * 1000;
	cache->capacity = cache->mask + 1;
	cache->usage = 0;
	cache->tmp_sim = 0;
	cache->threshold = threshold;

	cache->hash_lookups = 0;
	cache->hash_probes = 0;
	cache->hash_collisions = 0;
	
	cache->table = calloc(cache->capacity, sizeof(struct cache_entry));
	for (i = 0; i < cache->capacity; i++)
		cache->table[i].flags = CACHE_EMPTY;

	LOG("Cache Created, capacity: %d", cache->capacity);
	return cache;
}

void cache_destroy(struct cache *cache)
{
	free(cache->table);
	free(cache);
	LOG("Cache Destroyed");
}

void cache_stats(struct cache *cache, int *usage, unsigned int *similarity)
{
	int i;
	
	*usage=0;
	*similarity=0;
	*similarity = cache->tmp_sim;
	cache->tmp_sim = 0;

	for (i = 0; i < cache->capacity; i++) {
		if (!(IS_EMPTY(cache->table[i]) || is_expired(&cache->table[i]))) {
			*usage++;
			if (cache->table[i].count > 1 && !(cache->table[i].flags & CACHE_PIN)
				&& !(cache->table[i].flags & CACHE_IGNORE)) {
			    *similarity |= 1<<cache->table[i].count;
			}
		}
	}
}

int is_seen(struct cache_entry *cache_entry, u_int dst)
{
	if (cache_entry->flags & CACHE_MULTIPLE_DST) {
		// TODO consider sorting dst table
		// TODO consider storing only least significant bits from dst
		int i;

		for (i = 0; i < cache_entry->count; i++)
			if (cache_entry->dest->dst[i] == dst)
				return 1;
		return 0;
	} else {
		return cache_entry->dst == dst;
	}
}
