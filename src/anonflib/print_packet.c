#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "mapiipc.h"
#include "anonymization.h"


static int anonprint_reset(MAPI_UNUSED mapidflib_function_instance_t *instance) 
{
  return 0;
}

static int anonprint_cleanup(MAPI_UNUSED mapidflib_function_instance_t *instance) 
{
  return 0;
}

static int anonprint_init(MAPI_UNUSED mapidflib_function_instance_t *instance, MAPI_UNUSED int fd) {
  return 0;
}

static int anonprint_instance(MAPI_UNUSED mapidflib_function_instance_t *instance, MAPI_UNUSED int fd, MAPI_UNUSED mapidflib_flow_mod_t *flow_mod) {
	return 0;
}

static int anonprint_process(mapidflib_function_instance_t *instance, MAPI_UNUSED unsigned char* dev_pkt,unsigned char* link_pkt,mapid_pkthdr_t* pkt_head) {
	struct pcap_pkthdr pkthdr;
	mapipacket decoded_pkt;

	//printf("I am anonprint_process %d\n",pkt_head->caplen);
	pkthdr.caplen=pkt_head->caplen;
	pkthdr.len=pkt_head->wlen;
	pkthdr.ts.tv_sec=pkt_head->ts; //XXX taken from to_tcpdump, to be cross-checked
  	pkthdr.ts.tv_usec=pkt_head->ts;
	
	decode_packet(instance->hwinfo->link_type,instance->hwinfo->cap_length,&pkthdr,(unsigned char *)link_pkt,&decoded_pkt);	
	PrintPacket(stdout,&decoded_pkt,instance->hwinfo->link_type);

	return 1;
}

static mapidflib_function_def_t anonprintfinfo={
  "", //libname
  "PRINT_PACKET", //name
  "Prints a packet to standard output", //descr
  "", //argdescr
  MAPI_DEVICE_ALL, //devtype
  MAPIRES_NONE, //Method for returning results
  0, //shm size
  0, //modifies_pkts
  0, // filters packets
  MAPIOPT_AUTO, //Optimization
  anonprint_instance, //instance
  anonprint_init, //init
  anonprint_process, //process
  NULL, //get_result,
  anonprint_reset, //reset
  anonprint_cleanup, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* anonprint_get_funct_info();

mapidflib_function_def_t* anonprint_get_funct_info() {
  return &anonprintfinfo;
};

