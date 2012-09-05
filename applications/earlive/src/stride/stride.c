/*
 * (C) Akritid, All Rights Reserved
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include "mod_detect.h"

#include "offset_info.h"

#define dprintf(...) 
//#define dprintf printf

#define BUFSIZE 65536

//#define BRANCHTREE
//#define APE

// This belongs to decoder.c
//#define RELAX_SELF_MODIFICATION

#define OUT_OF_BOUNDS(index, bufsize) (!(index >= 0 && index < bufsize))
#define TREE_SAFE 1
#define TREE_UNSAFE 0

#define INF_LEN 10000


static int backpatch[BUFSIZE];
static int alignment = 4;
static int sequence_count;
static int sequence_length;
static int sled_len;
static int shellcode_len;

/*
 * Decode a sequence starting at offset until a terminating instruction is reached.
 * The sequence can be terminated by privileged/invalid instruction or by a
 * control flow transfer instruction.
 */
static void decode_offset(unsigned char *buf, int bufsize, struct offset_info *decode_cache, int offset)
{
	int pos;
	int inst_size;
	int backpatchcount;
	int i;

	backpatchcount = 0; // clear backpatch queue

	// decode sequence
	for (pos = offset; pos < bufsize; pos += inst_size) {
		struct offset_info *info = &decode_cache[pos];

		if (info->is_decoded) { // sequence converged
			pos = info->resolved_at;
			break;
		}

		info->is_decoded = 1;

		/* mark for backpatching when we determine sequence outcome */
		backpatch[backpatchcount++] = pos;

		inst_size = analyze(buf, bufsize, pos, info);

		if (inst_size == 0)
			break;
	}

	// backpatch
	for (i = 0; i < backpatchcount; i++) {
		decode_cache[backpatch[i]].resolved_at = pos;
	}
}

/*
 * Check whether the given buffer contains any ASCI NUL characters.
 */
static int is_nonzero_string(unsigned char *buf, int bufsize)
{
	int i;

	for (i = 0; i < bufsize; i++)
		if (buf[i] == '\0') {
			return 0;
		}
	return 1;
}

/*
 * Perform a detailed test to check whether there is actually
 * a sled at the given offset.
 */
static int is_really_sled(struct offset_info *decode_cache, int offset)
{
	int i;

	for (i = offset; i < sled_len; i += alignment) {
		if (decode_cache[i].seq_len < sled_len + shellcode_len - i)
			return 0;
	}
	return 1;
}


static int find_sled(unsigned char *buf, int bufsize, struct offset_info *decode_cache)
{
	int i, j, k, l;
	int sled_bytes_found;
	int sled_position;


	for (j = 0; j < alignment; j++) {
		sled_position = j;
		sled_bytes_found = 0;
		for (i = j; i < bufsize; i += alignment) {
			//printf("%d %d %d --", i, decode_cache[i].seq_len, sequence_length);
			if (decode_cache[i].seq_len >= sequence_length) {
				sled_bytes_found += alignment;
			} else {
				sled_position = i + alignment;
				sled_bytes_found = 0;
			}

			//printf("%d %d\n", sled_bytes_found, sequence_count);
			if (sled_bytes_found >= sequence_count) {
					if (is_nonzero_string(buf + sled_position, sequence_count)
#ifdef CHECK_SLED
					&& is_really_sled(decode_cache, sled_position)
#endif
					) {
						decode_cache[sled_position].sled = 1;
						return sled_position;
					}
			}
		}

	}
	return -1;
}

static int compute_seq_len(unsigned char *buf, int bufsize, struct offset_info *decode_cache, int offset)
{
	int outcome_offset;
	struct offset_info *outcome;
	int bytes;

	outcome_offset = decode_cache[offset].resolved_at;

	if (OUT_OF_BOUNDS(outcome_offset, bufsize)) {
		// sequence reached end of buffer
		return bufsize - offset;
	}

	outcome = &decode_cache[outcome_offset];

	bytes = outcome_offset - offset;

	if (outcome->is_branchcc == 0) { // leaf
		switch (outcome->outcome) {
		case 'm':
		case 'j':
		case 's':
			return INF_LEN;
			break;
		case 'p':
		case 'e':
		case 'i':
			return bytes;
			break;
		default:
			abort();
		}
        } else {
		return INF_LEN;
	}
}

static struct offset_info *decode_buffer(unsigned char *buf, int bufsize)
{
	int i = 0;
	static struct offset_info decode_cache[BUFSIZE];

	memset(decode_cache, 0, sizeof(struct offset_info) * bufsize);

	for (i = 0; i < bufsize; i++) {
		decode_offset(buf, bufsize, decode_cache, i);
	}

	for (i = 0; i < bufsize; i++) {
		decode_cache[i].seq_len = compute_seq_len(buf, bufsize, decode_cache, i);
	}

	return decode_cache;
}

void stride_init(void)
{
#ifdef APE
	detect_init();
#else
	decoder_init();
#endif
}

int stride_process(unsigned char *buf, int bufsize, int align, int _sled_len, int _shellcode_len, int s_factor)
{
#ifdef APE
	if (detect_sled(buf, bufsize)) {
		return 1;
	} else {
		return -1;
	}
#else
	struct offset_info *decode_cache;

	sequence_count = _sled_len - s_factor;
	if (sequence_count < 1) {
		abort();
	}
	sequence_length = _shellcode_len + s_factor;
	sled_len = _sled_len;
	shellcode_len = _shellcode_len;
	alignment = align;
	//printf("Processing %d %s\n", bufsize, buf);
	decode_cache = decode_buffer(buf, bufsize);
	//print_info(decode_cache, bufsize);
	return find_sled(buf, bufsize, decode_cache);
#endif
}

void stride_cleanup(void)
{
#ifdef APE
#else
	decoder_cleanup();
#endif
}

static void print_offset_info(struct offset_info *info)
{
	printf("Resolved at %d\n", info->resolved_at);
	printf("seq_len %d\n", info->seq_len);
}

static void print_info(struct offset_info *decoded, int bufsize)
{
	int i;

	for (i = 0; i < bufsize; i++) {
		print_offset_info(&decoded[i]);
	}
}
