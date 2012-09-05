#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "fifo.h"

#include <stdio.h>
#include "debug.h"

/** \brief FIFO constructor
	Allocates a new FIFO structure.

	\param s Number of slots in the FIFO
	\param alloc reference to memory allocation routine
	\param data data reference to be passed to memory allocation routine

	\return A new FIFO on success, or NULL if memory couldn't be allocated
*/
fifo_t *
fifo_new(size_t s,fifo_alloc_t alloc,void *data)
{
	fifo_t *fifo;
	size_t alloc_size;

	alloc_size = sizeof(fifo_t) + (s - 1) * sizeof(uint32_t);
	if ( (fifo = (fifo_t *)alloc(&alloc_size,data)) == NULL )
		return NULL;

	fifo->head = fifo->tail = 0;
	fifo->size = fifo->available = (alloc_size - sizeof(fifo_t) + sizeof(uint32_t))/sizeof(uint32_t);

	return fifo;
}


/** \brief FIFO destructor
	Frees a FIFO structure

	\param fifo FIFO to destroy
	\param dfree reference to memory de-allocation routine
	\param data data reference to be passed to memory de-allocation routine
*/
void
fifo_destroy(fifo_t *fifo,fifo_free_t dfree,void *data)
{
	dfree(fifo,data);
}


/** \brief Reset a FIFO

	\param fifo FIFO to reset
*/
void
fifo_reset(fifo_t *fifo)
{
	fifo->available = fifo->size;
	fifo->head = fifo->tail = 0;
}


/** \brief Cast a raw buffer to a FIFO

	\param raw Reference to raw buffer of data
	\param s Size of FIFO returned

	\return Reference to a FIFO
*/
fifo_t *
fifo_cast_new(void *raw,size_t s)
{
	fifo_t *fifo = (fifo_t *)raw;

	fifo->size = fifo->available = s;
	fifo->head = fifo->tail = 0;

	return fifo;
}


/** \brief Enqueue an item into a FIFO

	\param fifo FIFO to store item
	\param item Item to store

	\return 0 on success, or -1 if the FIFO is full
*/
int
fifo_enqueue(fifo_t *fifo,uint32_t item)
{
	if ( fifo->available == 0 )
		return -1;

	--fifo->available;
	fifo->data[fifo->tail] = item;
	if ( ++fifo->tail >= fifo->size )
		fifo->tail = 0;

	return 0;
}


/** \brief Dequeue an item out of a FIFO

	\param fifo FIFO to retrieve item from
	\param item Reference to store dequeued item

	\return 0 on success, or -1 is FIFO is empty
*/
int
fifo_dequeue(fifo_t *fifo,uint32_t *item)
{
	if ( fifo->available == fifo->size )
		return -1;
	
	*item = fifo->data[fifo->head];
  //DEBUG_CMD2(printf("FIFO: dequeue at index of %u of %u\n",fifo->head,*item));
	if ( ++fifo->head >= fifo->size )
		fifo->head = 0;
	++fifo->available;

	return 0;
}

/** \brief Peek the item on the head of a FIFO

	\param fifo FIFO to retrieve item from
	\param item Reference to store dequeued item

	\return 0 on success, or -1 is FIFO is empty
*/
int
fifo_peek(fifo_t *fifo,uint32_t *item)
{	
  if ( fifo->available == fifo->size )
		return -1;
	
	*item = fifo->data[fifo->head];
  //DEBUG_CMD2(printf("FIFO: peek at index %u of %u\n",fifo->head,*item));
	return 0;
}


/** \brief Safely dequeue an item out of a FIFO

	A bitmask is being AND'ed with the tail index of the FIFO to protect from
	illegally large index values.

	\param fifo FIFO to store item
	\param item Item to store
	\param mask Bitmask to be AND'ed with tail index

	\return 0 on success, or -1 if the FIFO is full
*/
int
fifo_safe_enqueue(fifo_t *fifo,uint32_t item,uint32_t mask)
{
	if ( fifo->available == 0 )
		return -1;

	--fifo->available;
	fifo->data[fifo->tail & mask] = item;
  //DEBUG_CMD2(printf("FIFO: safe enqueue at index %u of %u\n",fifo->tail & mask,item));
	if ( ++fifo->tail >= fifo->size )
		fifo->tail = 0;

	return 0;
}
