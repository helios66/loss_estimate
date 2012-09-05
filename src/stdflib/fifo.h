#ifndef FIFO_H
#define FIFO_H

#include <stddef.h>
#include <stdint.h>

struct fifo
{
	uint32_t head,
	tail;
	size_t size,
	available;
	uint32_t data[1];
};

typedef struct fifo fifo_t;

#define FIFO_HEAD_VALUE(f,m) ((f)->data[(f)->head & (m)])
#define FIFO_IS_EMPTY(f) ((f)->size == (f)->available)
#define FIFO_TAIL(f) (f)->tail
#define FIFO_SIZE(f) (f)->size
#define FIFO_HEAD(f) (f)->head
#define FIFO_AVAILABLE(f) (f)->available

typedef void *(*fifo_alloc_t)(size_t *,void *);
typedef void (*fifo_free_t)(void *,void *);

fifo_t *fifo_cast_new(void *,size_t);
fifo_t *fifo_new(size_t,fifo_alloc_t,void *);
void fifo_destroy(fifo_t *,fifo_free_t,void *);
extern inline void fifo_reset(fifo_t *);
extern inline int fifo_enqueue(fifo_t *,uint32_t);
extern inline int fifo_dequeue(fifo_t *,uint32_t *);
extern inline int fifo_peek(fifo_t *,uint32_t *);
extern inline int fifo_safe_enqueue(fifo_t *,uint32_t,uint32_t);

#endif
