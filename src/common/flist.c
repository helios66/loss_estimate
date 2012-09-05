#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "flist.h"
#include "debug.h"

int flist_append(flist_t *list,int id,void *data)
{
  flist_node_t *node;

  if(list == NULL) 
  {
      DEBUG_CMD(Debug_Message("flist_append in NULL list"));
      return -1;
  }
  
  if ( (node = (flist_node_t *) calloc(1,sizeof(flist_node_t))) == NULL )
      return -1;
  
  node->id=id;
  node->data = data;
  node->next = NULL;
  
  while(__sync_lock_test_and_set(&list->lock,1));
  if ( flist_head(list) == NULL )
    flist_head(list) = node;
  else
    (flist_tail(list))->next = node;
  
  flist_tail(list) = node;
  list->size++;
  list->lock = 0;
  
  return 0;
}

int flist_prepend(flist_t *list,int id,void *data)
{
	flist_node_t *node;
	
	if(list == NULL) 
	{
		DEBUG_CMD(Debug_Message("flist_prepend in NULL list"));
		return -1;
	}

	if ( (node = calloc(1,sizeof(flist_node_t))) == NULL )
		return -1;
	
	node->id=id;
	node->data = data;
  	while(__sync_lock_test_and_set(&list->lock,1));
	node->next = list->head;

	flist_head(list) = node;
	
	if ( flist_tail(list) == NULL )
		flist_tail(list) = node;
	list->size++;
  	list->lock = 0;

	return 0;
}

void *flist_pop_first(flist_t *list)
{
	void *d;
	flist_node_t *node;
	
	if(list == NULL) 
	{
		DEBUG_CMD(Debug_Message("flist_pop_first in NULL list"));
		return NULL;
	}

  	while(__sync_lock_test_and_set(&list->lock,1));
	if ( flist_head(list) == NULL )
	{
  		list->lock = 0;
		return NULL;
	}

	d = flist_data((node = flist_head(list)));
	flist_head(list) = flist_next(node);
	free(node);
	if ( --flist_size(list) == 0 )
	{
		/*if size = 0 list is dead*/
		flist_head(list) = flist_tail(list) = NULL;
	}
  	list->lock = 0;
	return d;
}

void flist_init(flist_t *list)
{
	if(list == NULL) 
	{
		DEBUG_CMD(Debug_Message("flist_init in NULL list"));
		return;
	}

	flist_head(list) = flist_tail(list) = NULL;
	flist_size(list) = 0;
	list->lock = 0;
}

void flist_destroy(flist_t *list)
{
	flist_node_t *node;
	
	if(list == NULL) 
	{
		DEBUG_CMD(Debug_Message("flist_destroy in NULL list"));
		return;
	}
	while(__sync_lock_test_and_set(&list->lock,1));
	while( (node = flist_head(list)) )
	{
		flist_head(list) = flist_next(node);
		free(node);
	}
	flist_head(list) = flist_tail(list) = NULL;
	flist_size(list) = 0;
	list->lock = 0;
}

void* flist_get(flist_t *list, int id)
{
	flist_node_t *node;
	
	if(list == NULL) 
	{
		DEBUG_CMD(Debug_Message("flist_get in NULL list"));
		return(NULL);
	}
	
	while(__sync_lock_test_and_set(&list->lock,1));
	node=flist_head(list);
  
  	while(node!=NULL) {
  	  if(node->id==id)
	  {
       	    list->lock = 0;
  	    return node->data;
    	  }
	  node=node->next;
  	}
 
  list->lock = 0;
  return NULL;
}

int flist_get_next_id(flist_t *list, int id)
{
  flist_node_t *node;
  
  if(list == NULL) 
  {
	  DEBUG_CMD(Debug_Message("flist_get_next_id in NULL list"));
	  return -1;
  }
   
  while(__sync_lock_test_and_set(&list->lock,1));
  node=flist_head(list);
  while(node!=NULL) 
  {
    if(node->id==id) 
    {
      node=node->next;
      if(node==NULL)
      {
  	list->lock = 0;
	return 0;
      }
      else
      {
  	list->lock = 0;
	return node->id;
      }
    }
    
    node=flist_next(node);
  }

  list->lock = 0;
  return 0;
}

void flist_move_before(flist_t *list,int before,int id) {
  void *data=flist_remove(list,id);

  if(data==NULL) {
	  DEBUG_CMD(Debug_Message("flist:: Cannot move not existent content"));
	  return;
  }

  flist_insert(list,id,data,before);
}


void* flist_remove(flist_t *list,int id)
{
  flist_node_t *node;
  flist_node_t *p=NULL;
  void *data;
	
	if(list == NULL) {
		DEBUG_CMD(Debug_Message("flist:: flist_remove in NULL list"));
		return(NULL);
	}
	
  	while(__sync_lock_test_and_set(&list->lock,1));
	node=flist_head(list);

  	while(node!=NULL) 
	{
    	  if(node->id==id) 
	  {
      		--flist_size(list);
      		data=node->data;
      		if(p==NULL) 
				flist_head(list)=node->next;
      		else 
				p->next=node->next;
		if(flist_tail(list)==node)
			flist_tail(list)=p;
      		free(node);      
  		list->lock = 0;
		return data;
    	}  
    	else 
	{ 
      		p=node;
      		node=flist_next(node);
    	}
  }

  list->lock = 0;
  return NULL;
}

int
flist_insert(flist_t *list, int id, void* data, int index)
{
	int i;
	flist_node_t* head;
	flist_node_t* prev=NULL;
	flist_node_t* node;
	
	if(!list) {
		DEBUG_CMD(Debug_Message("flist:: flist_insert in NULL list"));
		return -1;
	}
	

	if (index == 0)
		return flist_prepend(list, id, data);
	if (index >= flist_size(list))
		return flist_append(list, id, data);

	if ( (node = calloc(1,sizeof(flist_node_t))) == NULL )
		return -1;

	node->id = id;
	node->data = data;

  	while(__sync_lock_test_and_set(&list->lock,1));
	head = flist_head(list);
	for (i=0; head != NULL; head = flist_next(head), i++)
	{
		if (i == index)
		{
			node->next = head;
			prev->next = node;
		}
		prev = head;
	}
	flist_size(list)++;

  	list->lock = 0;
	return 0;
}

void flist_reverse(flist_t* list)
{
	flist_node_t* node=NULL;
	flist_node_t* prev=NULL;
	flist_node_t* next=NULL;

	if(list == NULL) {
		DEBUG_CMD(Debug_Message("flist_reverse in NULL list"));
		return;
	}
	
  	while(__sync_lock_test_and_set(&list->lock,1));
	if (flist_head(list) == NULL)
	{
  		list->lock = 0;
		return;
	}

	for (node=flist_head(list); node != NULL; node = next)
	{
		next = flist_next(node);
		flist_next(node) = prev;
		prev = node;
	}

	node = flist_head(list);
	flist_head(list) = flist_tail(list);
	flist_tail(list) = node;

  	list->lock = 0;
	return;
}

#ifdef DIMAPI
void *flist_search(flist_t *list, int (*comp)(void *, void *), void *user)
{
	flist_node_t *n;
	void *dataCopy;

	//while(__sync_lock_test_and_set(&list->lock,1));
	for(n = flist_head(list) ; n != NULL ; n = flist_next(n)) {
		if ( comp(flist_data(n), user) == 0 ) { 
			dataCopy = flist_data(n);
		//	list->lock = 0;
			return dataCopy;
		}
	}
	//list->lock = 0;
	return NULL;
}
#endif

