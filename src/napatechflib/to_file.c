#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <pthread.h>
#include "mapi_errors.h"
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"

typedef unsigned int       bool_t; /* NTCommonInterface missing typedef hack */
#include <packetdescriptor.h>

#define BUFSIZE 65535 /* 64kB */

typedef struct napa_instance {
	unsigned long long maxpkts;
	unsigned long long pkts;
	int file;
	unsigned int usedbuf;
	unsigned int max_length;
	unsigned char *buf,*next;
} napa_instance_t;

static int to_napa_instance(mapidflib_function_instance_t *instance,
			    MAPI_UNUSED int fd,
			    MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
	mapiFunctArg* a=instance->args;
	int type = getargint(&a);

	if(type==MFF_RAW || type==MFF_NAPATECH)
		return 0;
	else
		return MFUNCT_COULD_NOT_APPLY_FUNCT;
}

static int to_napa_init(mapidflib_function_instance_t *instance,
		        MAPI_UNUSED int fd)
//Initializes the function
{
	int *res;
	napa_instance_t *i=malloc(sizeof(napa_instance_t)); 

	i->next=i->buf=malloc(sizeof(unsigned char)*BUFSIZE);
	i->max_length = instance->hwinfo->cap_length + sizeof(PacketDescriptorType2_t);
	i->usedbuf=0;

	mapiFunctArg* fargs=instance->args;
	getargint(&fargs);

	//Open file for writing
	i->file=getargint(&fargs);

	if(i==NULL||i->file<0) {
		free(i);
		return MFUNCT_COULD_NOT_INIT_FUNCT;
	}

	i->maxpkts=getargulonglong(&fargs);
	i->pkts=0;
	instance->internal_data=i;
	res=instance->result.data;
	*res=1;

	return 0;
}

static int to_napa_process(mapidflib_function_instance_t *instance,
			   unsigned char* dev_pkt,
			   MAPI_UNUSED unsigned char* link_pkt,
			   MAPI_UNUSED mapid_pkthdr_t* pkthdr)
{
	int l;
	napa_instance_t *i=instance->internal_data;
	int *res=instance->result.data;
	PacketDescriptorType2_t *descriptor=(PacketDescriptorType2_t*)dev_pkt;

	if(i->pkts >= i->maxpkts && i->maxpkts!=0) {      
		/* Flush buffer to file */
		if (i->usedbuf > 0) {
			write(i->file,i->buf,i->next-i->buf);
			i->next=i->buf;
			i->usedbuf=0;
			/* Close file here? */
		}
		*res=0;
		return 1;
	}

	if(i->usedbuf + i->max_length <= BUFSIZE) {
		l=descriptor->StoredLength;
		memcpy(i->next,dev_pkt,l);
		i->next+=l;
		i->usedbuf+=l;
	} else {
		write(i->file,i->buf,i->next-i->buf);
		i->next=i->buf;
		i->usedbuf=0;
	}

	i->pkts++;

	return 1;
}

static int to_napa_cleanup(mapidflib_function_instance_t *instance) {
	napa_instance_t *i=instance->internal_data;

	/* Flush buffer to file */
	if (i->usedbuf > 0) {
		write(i->file,i->buf,i->next-i->buf);
		i->next=i->buf;
		i->usedbuf=0;
	}

	if (i!=NULL && i->file)
		close(i->file);

	free(i->buf);
	free(i);
	return 0;
}

static mapidflib_function_def_t finfo={
	"",			//libname
	"TO_FILE",		//function name
	"TO_FILE saves packetflow into NAPATECH (PacketDescriptorType2) trace file.\nParameters:\n\tfilename : char*\n\tmaxpkts: unsigned long long",
	"iwl",		//argdescr
	MAPI_DEVICE_NAPATECH,	//devtype
	MAPIRES_SHM,		//resulttype
	sizeof(int),		//shm size
	0,			//modifies_pkts
	0,			//filters packets
	MAPIOPT_AUTO,		//optimization
	to_napa_instance,
	to_napa_init,
	to_napa_process,
	NULL,			//get_result
	NULL,			//reset
	to_napa_cleanup,
	NULL,			//client_init
	NULL,			//client_read_result
	NULL			//client_cleanup
};

mapidflib_function_def_t* to_napa_get_funct_info();
mapidflib_function_def_t* to_napa_get_funct_info() {
	return &finfo;
};
