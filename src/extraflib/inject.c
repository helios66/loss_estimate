#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>		/* DLT_EN10MB */
#include <assert.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "protocols.h"
#include "mapi_errors.h"
#include <netinet/in.h>
#include <libnet.h>

struct inject_data {
	libnet_t *libnet_handler;
};


static int inject_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
	struct inject_data *data=((struct inject_data *)(instance->internal_data));
	libnet_t *h=data->libnet_handler;
	int ret;
	
	if(h==NULL) 
		return 0;

	ret = libnet_adv_write_link(h,dev_pkt,pkt_head->wlen);
	if(ret == -1 ) {
		printf(" Ubale to send packet: %s\n",strerror(errno));
		return 0;
	}
	return 1;
}

static int inject_instance(mapidflib_function_instance_t *instance,
			     MAPI_UNUSED int flow_descr,
			     mapidflib_flow_mod_t *flow_mod)
{
	mapiFunctArg *fargs = instance->args;
	return(0);
}

static int inject_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{
	mapiFunctArg *fargs = instance->args;
	char ebuf[256];
	libnet_t *h;	
	char *ifname = getargstr(&fargs);
	instance->internal_data = malloc(sizeof(struct inject_data));
	h=libnet_init(LIBNET_LINK_ADV,ifname,ebuf);
	if(h==NULL) {
		printf("Libnet can't open %s : %s",ifname,ebuf);
		return MFUNCT_INVALID_ARGUMENT_1; 
	}
	((struct inject_data *)(instance->internal_data))->libnet_handler=h;

	return 0;
}

static mapidflib_function_def_t injectfinfo={
    "", //libname
    "INJECT", //name
    "Injects a packet to an interface", //descr
    "s", //argdescr
    MAPI_DEVICE_ALL, //devoid
    MAPIRES_SHM, //Use shared memory to return results
    0, //shm size
    0, //modifies_pkts
    0, //filters packets
    MAPIOPT_AUTO, //Optimization
    inject_instance,  //instance
    inject_init, //init
    inject_process,
    NULL, //get_result,
    NULL,
    NULL, //cleanup
    NULL, //client_init
    NULL, //client_read_result
    NULL  //client_cleanup
};

mapidflib_function_def_t* inject_get_funct_info();

mapidflib_function_def_t* inject_get_funct_info() {
    return &injectfinfo;
};
