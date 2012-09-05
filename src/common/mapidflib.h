#ifndef _MAPIFLIB_H
#define _MAPIFLIB_H 1
#include "mapi.h"
#include "mapid.h"
#include "mapidlib.h"
#include "flist.h"

/**
  * \file mapidflib.h
  * \brief Defines all structures related to MAPI functions
  */

/**
  * \struct mapidflib_flow_mod mapidflib.h
  * \brief Structure used for modifying the list of functions applied to a MAPI flow
  */
typedef struct mapidflib_flow_mod {


  /** 
   * \brief Used for reordering the execution order of functions.
   *
   * A function can set this to indicate that this function  
   * should be processed before the function with function ID equel to the value of reorder.
   */
  int reorder; 

  /**
   * \brief Used for manual global optimization. 
   *
   * A function can search through already
   * active function applied to other functions and if it nd a function that is
   * identical it can set the value of identical so that it points to the ID of 
   * the identical function. Should be set to 0 if there are no identical 
   * functions.
   */
  int identical; 

  /**
   * \brief Used for deleting functions from the flow
   *
   * Pointer to an array of functions IDs that can be deleted from the flow.
   * This is usefull in case a hardware function can replace multiple 
   * software functions.
   */
  int *delete; 

  int delete_size; ///< Size of the delete array.

  /**
   * \brief Used for adding new MAPI functions to the flow
   *
   * Pointer to a function that can be used for adding new functions to the current flow. 
   * It is used in the same way as mapi_apply_function.
   */
  mapid_add_function add_funct;

  /**
   * \brief Argument for mapid_add_function
   *
   * Pointer to an instance of mapidlib. This is needed as an argument for mapid_add_function. 
   * As it is subject to change without notice it should NEVER be used directly by a MAPI function
   */
  mapidlib_instance_t *mi;
} mapidflib_flow_mod_t;

/**
 * \brief Structure for storing results for MAPI functions
 *
 * This structure contains the actual results from a MAPI function as well as information needed by the application
 * to get hold of the results
 */
typedef struct mapidflib_result {
  mapid_result_t info; ///< Information about results that is sent back  to the client
  void* data; ///< Pointer to memory that contains the result data
  unsigned long data_size; ///< Size of data that contains the result
} mapidflib_result_t;

/**
 * \brief Enum used for deciding how global anonymization should be handled for a function
 */
typedef enum { MAPIOPT_NONE, ///< Enum value indicating that no global optimization should be used
	       MAPIOPT_AUTO, ///< Enum value indicating that automatic global optimization should be used
	       MAPIOPT_MANUAL ///< Enum value indicating that manual global optimization should be used. Function using this method should use the identical field in the mapiflib_flow_mod structure for global optimization
} mapidflib_optimize_t;

/**
 * \brief Enum showing if a MAPI function is initialized
 */
typedef enum { MAPIFUNC_UNINIT, ///< Enum value indicating that the function is uninitialized
	       MAPIFUNC_INIT  ///< Enum value indicating that the function is initialized
} mapidflib_status_t;


/**
 * \brief Structure containing information related to the actual instance of a MAPI function
 */
typedef struct mapidflib_function_instance {
  mapidflib_status_t status; ///< status of initialization 

  /* All arguments passed to the function is serialized into this string. The
   * functions getargin, getargchar, getargulongulong and getargstr defined
   * in mapiipc.h can be used for retrieving the arguments.
   */
  mapiFunctArg args[FUNCTARGS_BUF_SIZE]; 
  mapidflib_result_t result; ///< Results returned by the function
  void* internal_data; ///< Data used internally by the function
  mapid_hw_info_t *hwinfo; ///< Pointer to information about the adapter the flow is running on
  unsigned long long pkts; ///< Number of packets that has been processed by the function
  unsigned long long processed_pkts; ///< Number of packets that has been processed by the function and passd through it.
  struct mapidflib_function_def* def; ///< Pointer to the function definition structure
  int ret; ///< The return value of the last time the function processed a packet
  int refcount; ///< Number of flows that references this function
  int apply_flags;      ///<copy of the flags argument of mapid_apply_function()

} mapidflib_function_instance_t;

/**
 * \brief Structure containing information about an applied MAPI function
 */
typedef struct mapidflib_function {
  int fd; //Flow descriptor
  int fid; //Function id
  int ref; //1 if reference to instance in other flow
  mapidflib_function_instance_t *instance;
} mapidflib_function_t;


typedef enum { MAPIRES_NONE,MAPIRES_IPC, MAPIRES_SHM, MAPIRES_FUNCT } mapi_result_method_t;

typedef struct mapidflib_function_def {
  char* libname; //Name of library
  char* name; //Name of function
  char* descr; //Description of function
  char* argdescr; //Description of function arguments
  char* devtype; //Device type that this function is implemented for
  mapi_result_method_t restype; //Method used for returning results to the client
  int shm_size; //Size of shared memory this function wants allocated
  short modifies_pkts; //1 if this function modifies packets
  short filters_pkts; //1 if this function filters packets. This means that functions that lets all packets pass should set this to 0
  mapidflib_optimize_t optimize; //Method used for global optimization


  //Pointer to the instance interface. This interface is called by
  //mapi_apply_function. It should do some simple syntax checking and report
  //back any need for shared memory. This is done by setting
  //instance->result.data_size=<size of shared memory>
  int (*instance)(mapidflib_function_instance_t *instance, //Function instance
		  int fd, //Flow descriptor
		  mapidflib_flow_mod_t *flow_mod); //Pointer to structure used for modifying functions applied to the flow
		  

  //Pointer to the init interface. This interface initializes the 
  //function and allocates resources.
  int (*init)(mapidflib_function_instance_t* instance, //Instance of function
		  int fd); //Flow descriptor 

  //Pointer to the process interface. Processes a packet.
  int (*process)(mapidflib_function_instance_t* instance,
		 unsigned char* dev_pkt,
		 unsigned char* link_pkt,
		 mapid_pkthdr_t* pkt_head);  

  //Pointer to the get_result interface. Returns the results
  int (*get_result)(mapidflib_function_instance_t* instance,mapidflib_result_t **res);

  //Pointer to the reset interface. Resets the results of the function.
  int (*reset)(mapidflib_function_instance_t* instance);

  //Pointer to the cleanup interface. Frees resources when function
  //is removed
  int (*cleanup)(mapidflib_function_instance_t* instance);

  //Pointer to the client_init interface. Initializes function specific
  //read_result on the client side. Optional
  int (*client_init)(mapidflib_function_instance_t *instance, void* data);

  //Pointer to the client read_result interface. Returns a pointer to the results
  //for use inside the client mapi stub. Optional
  int (*client_read_result)(mapidflib_function_instance_t* instance,
			    mapi_result_t *res);

  //Pointer to the client_cleanup interface. Cleans up resources after
  //function specific read_result on the client side. Optional
  int (*client_cleanup)(mapidflib_function_instance_t* instance);
} mapidflib_function_def_t;

typedef struct mapdiflib_functionlist {
    mapidflib_function_def_t* def;
    struct mapdiflib_functionlist* next;
} mapidflib_functionlist_t;
    
typedef struct mapidflib_info {
    char* name; //Name of library
    char* descr; //Description of library
    unsigned num; //Number of functions contained in this library
} mapidflib_info_t;

mapidflib_functionlist_t* mapidflib_get_function_list();


extern char *mapidflib_get_libname();
extern char* mapidflib_get_lib_name(int libnumber);
//mapi_function_def_mini_t* mapidflib_get_function_info(int libnumber,int functionnumber);

#endif
