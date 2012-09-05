#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"

static int pktc_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
    (*(unsigned long long*)instance->result.data)++;
    return 1;
}

static int pktc_reset(mapidflib_function_instance_t *instance) 
{
    (*(unsigned long long*)instance->result.data)=0;
    return 0;
}

static mapidflib_function_def_t finfo={
    "", //libname
    "PKT_COUNTER", //name
    "Counts number of packets\n\tReturn value: unsigned long long", //descr
    "", //argdescr
    MAPI_DEVICE_ALL, //devoid
    MAPIRES_SHM, //Use shared memory to return results
    sizeof(unsigned long long), //shm size
    0, //modifies_pkts
    0, //filters packets
    MAPIOPT_NONE, //Optimization
    NULL,  //instance
    NULL, //init
    pktc_process,
    NULL, //get_result,
    pktc_reset,
    NULL, //cleanup
    NULL, //client_init
    NULL, //client_read_result
    NULL  //client_cleanup
};

mapidflib_function_def_t* pktc_get_funct_info();

mapidflib_function_def_t* pktc_get_funct_info() {
    return &finfo;
};



