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
#include "debug.h"
#include "mapiipc.h"
#include "mstring.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "log.h"
#include "trackflib.h"

static int ipoverip_init(MAPI_UNUSED mapidflib_function_instance_t *instance, MAPI_UNUSED int fd) {
	return 0;
}	

static int ipoverip_process(MAPI_UNUSED mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			unsigned char* pkt,
			mapid_pkthdr_t* pkt_head)
{
	int len = pkt_head->wlen;
	unsigned char *p = NULL;

	uint16_t ethertype;
	struct ether_header *ep = NULL;
	struct iphdr *iph = NULL;
	
	unsigned int saddr, daddr;
	
	struct in_addr source, dest;

	p = pkt;

	// lay the Ethernet header struct over the packet data
	ep = (struct ether_header *)p;

	// skip ethernet header
	p += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);

	ethertype = ntohs(ep->ether_type);

	if(ethertype == MPLS_MASK) {
			p += 4;
	}
	else if(ethertype != ETHERTYPE_IP) {
		return 0;
	}
	
	// IP header struct over the packet data;
	iph = (struct iphdr*)p;

	saddr = *((unsigned int *)&(iph->saddr));
	daddr = *((unsigned int *)&(iph->daddr));

	source.s_addr = (unsigned long int)iph->saddr ;
	dest.s_addr = (unsigned long int)iph->daddr;

	p += iph->ihl * 4;
	len -= iph->ihl *4;
	
	if(iph->protocol == 4)	// TCP
	{
		// Found an IP-in-IP encaptulated packet
		DEBUG_CMD(Debug_Message("found %d", iph->protocol));
		return 1;
	}
	else
	{
		return 0;
	}


	return 0;
}

static int ipoverip_cleanup(MAPI_UNUSED mapidflib_function_instance_t *instance) {
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "TRACK_IPOVERIP",
  "Searches for IP-in-IP encaptulated packets\n",
  "",
  MAPI_DEVICE_ALL,
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_NONE,
  NULL,
  ipoverip_init,
  ipoverip_process,
  NULL, //get_result
  NULL, //reset
  ipoverip_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* ipoverip_get_funct_info();
mapidflib_function_def_t* ipoverip_get_funct_info() {
  return &finfo;
};

