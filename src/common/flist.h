/**
 * \file flist.h 
 * \brief Library for handling linked lists where each node is identified by an integer ID
 */

#ifndef _FLIST_H
#define _FLIST_H 1
#include <pthread.h>


/**
 * \struct flist_node flist.h
 * \brief Structure containing the data for one single node in an flist
 */
typedef struct flist_node
{
  int id; //!< ID of the node
  void *data; //!< Pointer to the data stored in the node
  struct flist_node* next;  //!< Pointer to the next node. NULL if no other nodes exits
} flist_node_t;

/**
 * \struct flist flist.h
 * \brief Structure containing control information about an flist
 */
typedef struct flist
{
  flist_node_t *head; //!< Pointer to head of list
  flist_node_t *tail; //!< Pointer to tail of list
  int size; //!< Number of elements in the list
  int lock;
} flist_t;

//! Macro to get the head node of a list l
#define flist_head(l) (l)->head
//! Macro to get the tail node of a list l
#define flist_tail(l) (l)->tail
//! Macro to get the size of a list l
#define flist_size(l) (l)->size
//! Macro to get the next node after n
#define flist_next(n) (n)->next
//! Macro to get the data of node n
#define flist_data(n) (n)->data
/// Macro to get the ID of node n
#define flist_id(n) (n)->id



/**
 * \brief Initialise an flist
 * \param list the list to initialize
 */
void flist_init(flist_t *list);

/** \brief Destroy and de-allocate the memory hold by a list
  * \param list a pointer to an existing list
  */
void flist_destroy(flist_t *list);

/** \brief Remove a node from the list
  * \param list a pointer to an existing list
  */
void* flist_remove(flist_t *list,int);

/** \brief Insert a new node into the list
  * \param list a pointer to an existing list
  * \param id ID of the new node
  * \param data data to be stored in the node
  * \param index specifies the exact index of the list where the node should be inserted
  * \return 0 on success, or -1 on failure
  */
int  flist_insert(flist_t *list, int id, void *data, int list_index);

/** \brief Reverse the order of the list
  * \param list a pointer to an existing list
  */
void flist_reverse(flist_t *list);

/** \brief Moves one node before another one in the list
  * \param list a pointer to an existing list
  * \param before ID of the node that the other node should be moved before
  * \param id ID of the node that should be moved
  */
void flist_move_before(flist_t *list,int before,int id);

/** \brief Pop the first element in the list
  * \param list a pointer to a list
  * \return a pointer to the element, or NULL if the list is empty
  */
extern inline void *flist_pop_first(flist_t *);

/** \brief Append data to list
  * \param list a pointer to a list
  * \param data the data to place in the list
  * \return 0 on success, or -1 on failure 
  */
extern inline int flist_append(flist_t *list,int id,void *data);

/** \brief Prepend data to list
  * \param list a pointer to list
  * \param data the data to place in the list
  * \return 0 on success, or -1 on failure
  */
extern inline int flist_prepend(flist_t *list,int id,void *data);

/** \brief Get the data of a node from the list
  * \param list a pointer to list
  * \param id ID of the node to get
  * \return pointer to the data of the node. 0 if the node do not exist
  */
extern inline void* flist_get(flist_t *list,int id);

/** \brief Get the data of the next node in the list
  * \param list a pointer to list
  * \param id ID of the previous node
  * \return pointer to the data of the node. 0 if the node do not exist
  */
extern inline int flist_get_next_id(flist_t *list,int id);

#ifdef DIMAPI
/** \brief Searches for a mathcing node and returns it
	Returns only the first matching node.

	\param list a pointer to an existing list
	\param comp function reference to be used for comparison of nodes
	\param cdata 2nd argument to be passed to comparison function

	\return Reference to the matching node's data, or NULL if no node 
	was matched
*/
extern inline void *flist_search(flist_t *, int (*compar)(void *, void *), void *);
#endif

#endif
