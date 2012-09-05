#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "mapi_errors.h"

#define bool_t unsigned int
#include <packetdescriptor.h>

typedef struct {
  int ifindex;
} interface_instance_t;

static int interface_instance(mapidflib_function_instance_t *instance,
                              MAPI_UNUSED int fd,
                              MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
	mapiFunctArg* fargs;
	int ifindex;

	fargs = instance->args;
	ifindex = getargint(&fargs);

	/* refuse: bad port specification */
	if(ifindex < 0)
		return MFUNCT_INVALID_ARGUMENT;

	return 0;
}

static int interface_init(mapidflib_function_instance_t *instance,
                          MAPI_UNUSED int fd)
{
	interface_instance_t *internal_data_ptr;
	mapiFunctArg* fargs;
	int ifindex;

	if((instance->internal_data = malloc(sizeof(interface_instance_t))) == NULL) {
		fprintf(stderr, "interface_init(): could not allocate internal data.\n");
		return MAPID_MEM_ALLOCATION_ERROR;
	}

	internal_data_ptr = (interface_instance_t *) (instance->internal_data);

	fargs = instance->args;
	ifindex = getargint(&fargs);

	internal_data_ptr->ifindex = ifindex;

	return 0;
}

static int interface_process(mapidflib_function_instance_t *instance,
	MAPI_UNUSED unsigned char* dev_pkt,
	MAPI_UNUSED unsigned char* link_pkt,
	mapid_pkthdr_t* pkt_head)
{
	interface_instance_t *internal_data_ptr;
	internal_data_ptr = (interface_instance_t *) (instance->internal_data);

	if (pkt_head->ifindex == internal_data_ptr->ifindex)
		return 1;

	return 0;
}

static int interface_cleanup(mapidflib_function_instance_t* instance)
{
	if (instance->internal_data != NULL) {
		free(instance->internal_data);
		instance->internal_data = NULL;
	}
	return 0;
}

static mapidflib_function_def_t finfo={
	"", //libname
	"INTERFACE", //name
	"Filters packets from specific interfaces on an adapter", //descr
	"i", //argdescr
	MAPI_DEVICE_NAPATECH_NT, //devtype
	MAPIRES_NONE, //Method for returning results
	0, //shm size
	0, //modifies_pkts
	1, //filters packets
	MAPIOPT_AUTO,
	interface_instance, //instance
	interface_init, //init
	interface_process, //process
	NULL, //get_result,
	NULL, //reset
	interface_cleanup, //cleanup
	NULL, //client_init
	NULL, //client_read_result
	NULL  //client_cleanup
};

mapidflib_function_def_t* interface_get_funct_info();
mapidflib_function_def_t* interface_get_funct_info() {
	return &finfo;
};
