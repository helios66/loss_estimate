#ifndef RABIN_H
#define RABIN_H

/*
 * Incremental Rabin fingerprints.
 */

#define SHIFT_IN_MUL(r, h, c) (h = h*257 + c)
#define SHIFT_IN_SHIFT_ADD(r, h, c) (h = (((h << 8)|c) + h))
#define SHIFT_IN_UNSAFE(r, h, c) (h = (h<<1) + c)

#define SHIFT_OUT_MUL(r, h, c) (h -= (c *r->shift_out_multiplier))
#define SHIFT_OUT_TABLE(r, h, c) (h -= r->table[c])
#define SHIFT_OUT_UNSAFE(r, h, c) (h -= (c << (r->span_size-1)))

#define SHIFT_IN SHIFT_IN_SHIFT_ADD
#define SHIFT_OUT SHIFT_OUT_TABLE

//#define SHIFT_IN SHIFT_IN_UNSAFE
//#define SHIFT_OUT SHIFT_OUT_UNSAFE


#include <stdlib.h>

typedef struct rabin {
	int span_size;
	u_int32_t shift_out_multiplier;
	u_int32_t table[256];
} rabin_t;

rabin_t *rabin_create(int span_size);

#endif /* RABIN_H */
