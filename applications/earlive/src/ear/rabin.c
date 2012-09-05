/*
 * Incremental Rabin fingerprints.
 */

#include <stdlib.h>
#include "rabin.h"

// span_size: how many input characters to consider at once
rabin_t *rabin_create(int span_size)
{
	rabin_t *r;
	int i;

	r = malloc(sizeof(rabin_t));

	r->span_size = span_size;

	/* shift_out_multiplier = 257^(span_size-1) (mod 2^32) */
	r->shift_out_multiplier = 1;
	for (i = 0; i < span_size - 1; i++)
		r->shift_out_multiplier *= 257;

	/* table[i] = i * shift_out_multiplier (mod 2^32) */
	for (i = 0; i < 256; i++)
		r->table[i] = i * r->shift_out_multiplier;

	return r;
}
