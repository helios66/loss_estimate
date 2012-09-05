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
#include "acsmx2.h"
#include "mapi_errors.h"

#include <pcap.h>
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

static int web_process(MAPI_UNUSED mapidflib_function_instance_t *instance,
			MAPI_UNUSED  unsigned char* dev_pkt,
			 unsigned char* pkt,
			mapid_pkthdr_t* pkt_head)
{
	int len = pkt_head->caplen;
	unsigned char *p = NULL;

	uint16_t ethertype;
	struct ether_header *ep = NULL;
	struct pos_header {
		uint16_t af;
		uint16_t cf;
	}	*pp = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	
	struct vlan_802q_header *vlan_header;

	unsigned int saddr, daddr;
	struct in_addr source, dest;

	uint16_t sp, dp;

	int	pkt_color = pkt_head->color;
	
	if(pkt_color != 0 && pkt_color != WEB_COLOR) {
		return 0;
	}

	p = pkt;

	switch(instance->hwinfo->link_type) {
		case DLT_EN10MB:
				// lay the Ethernet header struct over the packet data
				ep = (struct ether_header *)p;

				// skip ethernet header
				p += sizeof(struct ether_header);
				len -= sizeof(struct ether_header);

				ethertype = ntohs(ep->ether_type);

				if(ethertype  == ETHERTYPE_8021Q) {
					vlan_header = (struct vlan_802q_header*)p;
					ethertype = ntohs(vlan_header->ether_type);
					p += sizeof(struct vlan_802q_header);
				}
				
				if(ethertype == MPLS_MASK) {
					p += 4;			
				}
				else if(ethertype != ETHERTYPE_IP) {
					return 0;
				}
			break;
		case DLT_CHDLC:
				pp = (struct pos_header *)p;

				p += sizeof(struct pos_header);
				len -= sizeof(struct pos_header);

				ethertype = ntohs(pp->cf);

				if (ethertype != ETHERTYPE_IP) {
					return 0;
				}
			break;
		default:
			//DEBUG_CMD(Debug_Message("Link layer not supported"));
			return 0;
	}
	
	// IP header struct over the packet data;
	iph = (struct iphdr*)p;

	saddr = *((unsigned int *)&(iph->saddr));
	daddr = *((unsigned int *)&(iph->daddr));

	source.s_addr = (unsigned long int)iph->saddr;
	dest.s_addr = (unsigned long int)iph->daddr;

	p += iph->ihl * 4;
	len -= iph->ihl * 4;

	if(iph->protocol == 6)	// TCP
	{
		tcph = (struct tcphdr *)p;
		
		sp = ntohs(tcph->source);
		dp = ntohs(tcph->dest);

		p += tcph->doff * 4;

		if((unsigned int)(p - pkt) == pkt_head->caplen) {
			return 0;
		}
		len -= tcph->doff * 4;
	}
	else
	{
		return 0;
	}

	if(sp == 80 || sp == 443 || dp == 80 || dp == 443) {
		// this is web (almost for sure since it is not any of the P2P
		// portocols)

#ifdef __TRACKFLIB_LOGGING__
		write_to_log("WEB", "WEB", iph->protocol, source, sp, dest, dp, pkt, len); 
#endif
		pkt_head->color = WEB_COLOR;

		return 1;
	}

	return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "TRACK_WEB",
  "Looks for Web packets\n",
  "",
  MAPI_DEVICE_ALL,
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_NONE,
  NULL,
  NULL, // init
  web_process,
  NULL, //get_result
  NULL, //reset
  NULL, // cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* web_get_funct_info();
mapidflib_function_def_t* web_get_funct_info() {
  return &finfo;
};

