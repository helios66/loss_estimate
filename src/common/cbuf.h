#ifndef CBUF_H
#define CBUF_H

#include <stddef.h>
#include <stdint.h>

#include "kernel_memory.h"

struct cbuf
{
	size_t available,
	unit_size,
	size;
	uint32_t head,
	tail;
	kernel_memory_t *kmem;
	unsigned char *data;
};

typedef struct cbuf cbuf_t;

#define CBUF_HEAD(c)  (c)->head
#define CBUF_TAIL(c)  (c)->tail
#define CBUF_SIZE(c)  (c)->size
#define CBUF_UNIT_SIZE(c) (c)->unit_size
#define CBUF_SLOT(c,i) ((c)->data + (i) * (c)->unit_size)
#define CBUF_AVAILABLE(c) (c)->available
#define CBUF_DATA(c) (c)->data
#define CBUF_KMEM(c) (c)->kmem

#define CBUF_PERMS 0660

cbuf_t *cbuf_new(size_t,size_t,kernel_memory_alloc_t,kernel_memory_t *);
void cbuf_destroy(cbuf_t *,kernel_memory_free_t);
extern inline void cbuf_leave_slots(cbuf_t *,uint32_t);
extern inline int32_t cbuf_store(cbuf_t *,const void *,size_t);
extern inline int32_t cbuf_store2(cbuf_t *,const void *,size_t,const void *,size_t);

#endif
