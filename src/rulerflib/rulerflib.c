/* File: rulerlib.c
 *
 * Compile and launch Ruler filters.
 */

typedef volatile int pthread_spinlock_t;

#include <dlfcn.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>

#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "mapiipc.h"
#include "mapi_errors.h"
#include "fhelp.h"

static char libname[] = "rulerlauncher";

extern mapidflib_function_def_t* ruler_get_funct_info();

static mapidflib_functionlist_t functions[1];

#include "helper-functions.h"


mapidflib_functionlist_t* mapidflib_get_function_list()
{
    functions[0].def = ruler_get_funct_info();
    functions[0].def->libname = libname;
    functions[0].next = NULL;

    return &functions[0];
}

char *mapidflib_get_libname()
{
    return libname;
}

/* Given the argument list of our function instance, return the name of
 * the template to use, or NULL if the template name is incorrect.
 */
static const char *check_parameter( unsigned char *arg )
{
    // FIXME: Check sanity of source file.
    return (char *) arg;
}

/* A new instance of this function has been created. Now is a great time
 * to check parameters and give some information.
 */
static int ruler_instance(
  mapidflib_function_instance_t *instance,
  int fd,
  mapidflib_flow_mod_t *flow_mod
)
{
#if TRACE_MAPI_CALLS
    printf( "ruler_instance()\n" );
#endif

    (void) fd;
    (void) flow_mod;
    mapiFunctArg *fargs = instance->args;
    char *str = getargstr( &fargs );
    if( str == NULL || str[0] == '\0' ){
        return MFUNCT_INVALID_ARGUMENT_1;
    }

    const char *arg = check_parameter( instance->args );
    if( arg == NULL ){
        return MFUNCT_INVALID_ARGUMENT_1;
    }
    return 0;
};

/* Initialize this instance of our function. */
static int ruler_init( mapidflib_function_instance_t *instance, int fd )
{
    (void) fd;
    instance_info *info;
    mapiFunctArg *fargs = instance->args;
    const char *source_file = getargstr( &fargs );

    if( source_file[0] == '\0' ){
        return MFUNCT_INVALID_ARGUMENT_1;
    }

    info = create_ruler_filter( source_file );

    if( info == NULL ){
        // FIXME: is there an official MAPI return code that matches this?
        return 1;
    }

    // Store a pointer to the instance_info in the mapi administration structure.
    instance->internal_data = info;

    return 0;
}

/* Process a MAPI packet. */
static int ruler_process(
 mapidflib_function_instance_t *instance,
 unsigned char *dev_pkt,
 unsigned char *link_pkt,
 mapid_pkthdr_t *pkt_head
)  
{
    instance_info *info = (instance_info *) instance->internal_data;
    unsigned char *new_link_pkt = (unsigned char*) link_pkt; // XXX YUCK!
    unsigned char *outbuf;
    unsigned int outlen;

    (void) dev_pkt;
#if TRACE_MAPI_CALLS
    printf( "Ruler launcher packet processor called.\n" );
#endif

    // FIXME: cache the buffer.
    outbuf = malloc( (size_t) pkt_head->caplen );
    if( outbuf == NULL ){
        fprintf( stderr, "Out of memory" );
        return 0;
    }
    int res = (*info->processor)( link_pkt, pkt_head->caplen, outbuf, &outlen );

    if( res ){
#if TRACE_MAPI_CALLS
        printf( "Copying %u bytes from address %p to address %p\n", outlen, outbuf, new_link_pkt );
#endif
        memcpy( new_link_pkt, outbuf, outlen );
        pkt_head->caplen = outlen;
    }
    free( outbuf );
    return res == 0;
}

static int ruler_reset( mapidflib_function_instance_t *instance ) 
{
#if TRACE_MAPI_CALLS
    printf( "Ruler launcher reset called (this function is empty).\n" );
#endif
    (void) instance;
    return 0;
}

static int ruler_cleanup( mapidflib_function_instance_t *instance ) 
{
#if TRACE_MAPI_CALLS
    printf( "Ruler launcher cleanup called.\n" );
#endif
    instance_info *info = (instance_info *) instance->internal_data;
    destroy_ruler_filter( info );
    return 0;
}

static mapidflib_function_def_t finfo = {
    .libname = "", //FIXME: libname
    .name = "RULER", //name
    .descr = "Ruler filter compiler and launcher", //descr
    .argdescr = "s", //argdescr
    .devtype = MAPI_DEVICE_ALL, //devtype
    .restype = MAPIRES_NONE, //Method for returning results
    .shm_size = 0, //shm size
    .modifies_pkts = 1, //modifies_pkts
    .filters_pkts = 1, //filters_pkts
    .instance = ruler_instance, //instance
    .init = ruler_init, //init
    .process = ruler_process, //process
    .get_result = NULL, //get_result,
    .reset = ruler_reset, //reset
    .cleanup = ruler_cleanup, //cleanup
    .client_init = NULL, //client_init
    .client_read_result = NULL, //client_read_result
    .client_cleanup = NULL  //client_cleanup
};

mapidflib_function_def_t* ruler_get_funct_info()
{
    return &finfo;
};


__attribute__ ((constructor))
     void init ()
{
    printf ("Library rulerflib loaded\n");
}

__attribute__ ((destructor))
     void fini ()
{
    printf ("Library rulerflib unloaded\n");
}

