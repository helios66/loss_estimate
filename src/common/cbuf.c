#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "cbuf.h"
#include "debug.h"
#include <stdio.h>

/** \brief cbuf constructor
	Allocates a new cbuf structure and data buffer

	\param n number of slots to be allocated in the data buffer
	\param usize maximum size of storable unit
	\param alloc reference to memory allocation routine
	\param alloc_data data reference to be passed to memory allocation routine

	\return A new cbuf on success, or NULL if memory couldn't be allocated
*/
cbuf_t *
cbuf_new(size_t n,size_t usize,kernel_memory_alloc_t alloc,kernel_memory_t *alloc_data)
{
	cbuf_t *cbuf;
	size_t buflen;

	if ( (cbuf = (cbuf_t *)malloc(sizeof(cbuf_t))) == NULL )
		return NULL;

	buflen = n * usize;
	if ( alloc && alloc_data )
	{
		cbuf->data = (unsigned char *)alloc(&buflen,alloc_data);
		cbuf->kmem = alloc_data;
	}
	else
	{
		cbuf->data = (unsigned char *)malloc(buflen);
		cbuf->kmem = NULL;
	}

	if ( cbuf->data == NULL )
	{
		free(cbuf);
		return NULL;
	}

	cbuf->unit_size = usize;
	cbuf->available = cbuf->size = (buflen / usize);
	cbuf->head = cbuf->tail = 0;

	return cbuf;
}


/** \brief cbuf destructor
	Frees a cbuf structure and data buffer

	\param cbuf cbuf to destroy
	\param dfree reference to memory de-allocation routine
	\param alloc_data data reference to be passed to memory de-allocation routine
*/
void
cbuf_destroy(cbuf_t *cbuf,kernel_memory_free_t dfree)
{
	if ( dfree && cbuf->kmem )
		dfree(cbuf->kmem);
	else
		free(cbuf->data);
	free(cbuf);
}


/** \brief Store item in the cbuf

	\param cbuf the cbuf to store the item into
	\param item reference to the item to be stored

	\return the index where the item was stored on success,
	or less than zero on failure. Possible errors:
	\li -ENOMEM there is no slot available in the cbuf
	\li -EINVAL data item to be stored exceeds maximum cbuf unit size
*/
int32_t
cbuf_store(cbuf_t *cbuf,const void *data,size_t datalen)
{
	int index;

	// Not enough space
	if ( cbuf->available == 0 )
		return - ENOMEM;

	// Invalid data size
	if ( datalen > cbuf->unit_size )
		return - EINVAL;
	
	--cbuf->available;
	memcpy(cbuf->data + (cbuf->tail * cbuf->unit_size),data,datalen);
	index = (int32_t)cbuf->tail;
	if ( ++cbuf->tail >= cbuf->size )
		cbuf->tail = 0;

	return index;
}

/** \brief Store item concisting of 2 parts in the cbuf

	\param cbuf the cbuf to store the item into
	\param data1 first part of item to be stored
	\param data1len size of first part
	\param data2 second part of item to be stored
	\param data2len size of second part

	\return the index where the item was stored on success,
	or less than zero on failure. Possible errors:
	\li -ENOMEM there is no slot available in the cbuf
	\li -EINVAL data item to be stored exceeds maximum cbuf unit size
*/
int32_t
cbuf_store2(cbuf_t *cbuf,const void *data1,size_t data1len,const void *data2,size_t data2len)
{
	int32_t index;

	// Not enough space
	if ( cbuf->available == 0 )
		return - ENOMEM;

	// Invalid data size
	if ( (data1len + data2len) > cbuf->unit_size )
		return - EINVAL;
	
	--cbuf->available;
  //DEBUG_CMD2(printf("Storing packet at %u\n",cbuf->tail * cbuf->unit_size));
	memcpy(cbuf->data + (cbuf->tail * cbuf->unit_size),data1,data1len);
	memcpy(cbuf->data + (cbuf->tail * cbuf->unit_size) + data1len,data2,data2len);
	index = (int32_t)cbuf->tail;
	if ( ++cbuf->tail >= cbuf->size )
		cbuf->tail = 0;

	return index;
}


/** \brief Forward the read pointer of a CBUF to make room available

	\param cbuf the cbuf to store the item into
	\param slots number of slots to make available
*/
void
cbuf_leave_slots(cbuf_t *cbuf,uint32_t slots)
{
	cbuf->available += slots;
	if ( cbuf->available > cbuf->size )
		cbuf->available = cbuf->size;
	cbuf->head += slots;
	if ( cbuf->head >= cbuf->size )
		cbuf->head -= cbuf->size;
}
