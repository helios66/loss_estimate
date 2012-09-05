#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <net/ethernet.h>	/* struct ether_header */
#include <net/if_arp.h>		/* struct arphdr */
#include <netinet/ip.h>		/* struct iphdr */
#include <netinet/tcp.h>	/* struct tcphdr */
#include <netinet/udp.h>	/* struct udphdr */
#include <netinet/ip_icmp.h>	/* struct icmp */
#include <assert.h>
#include <pcap.h>               /* DLT_EN10MB */
#include "mapi_errors.h"

#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"

// check of argument that is passed to the function
static int hash_instance(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd, MAPI_UNUSED mapidflib_flow_mod_t *flow_mod){
	
	int arg;
	mapiFunctArg *fargs = instance->args;

	arg = getargint(&fargs);
	
	if (arg < 0 || arg > 3)
		return MFUNCT_INVALID_ARGUMENT_1;
	
	return 0;
}

static int hash_init(mapidflib_function_instance_t * instance,
		     MAPI_UNUSED int fd)
//Initializes the function
{

    unsigned int *hashv;
    int arg;

    /* parse argument */
    // 0 - hash packet at link layer
    // 1 - hash packet at network layer
    // 2 - hash packet at transport layer (IP/ARP/RARP payload)
    // 3 - hash packet at application layer (TCP/UDP/ICMP payload)
    mapiFunctArg *fargs = instance->args;
    arg = getargint(&fargs);

    hashv = instance->result.data;
    (*hashv) = 0;

    if (arg < 0 || arg > 3) {
        return MFUNCT_INVALID_ARGUMENT_1;
    }
    return 0;
}

static int hash_process(mapidflib_function_instance_t * instance,
			unsigned char *dev_pkt,
			MAPI_UNUSED unsigned char *link_pkt,
			mapid_pkthdr_t * pkt_head)
{
    unsigned int len, i, prime = 500009;
    unsigned int hash, *ptr;

    struct ether_header *eth;
    struct iphdr *iph;
    struct arphdr *arph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmp *icmph;
    unsigned char *payload;
    unsigned int payloadlen;

    unsigned char *data = 0x00;	// data to hash
    unsigned int datalen = 0;

    len = pkt_head->caplen;	// entire packet's length

    /* parse argument */
    // 0 - hash packet at link layer
    // 1 - hash packet at network layer
    // 2 - hash packet at transport layer (IP/ARP/RARP payload)
    // 3 - hash packet at application layer (TCP/UDP/ICMP payload)
    mapiFunctArg *fargs = instance->args;
    int option = getargint(&fargs);

    if (option < 0 || option > 3) {
	return MFUNCT_INVALID_ARGUMENT_1;
    }

    if (option == 0) { // hash entire device packet
	data = dev_pkt;
	datalen = pkt_head->caplen;
    }
    else if (option == 1) {
	if (instance->hwinfo->link_type == DLT_EN10MB) /* ethernet */ {
	    datalen = pkt_head->caplen - sizeof(struct ether_header);
	    data = (u_char*)(dev_pkt + sizeof(struct ether_header));
	} else if (instance->hwinfo->link_type == DLT_CHDLC) {
	    datalen = pkt_head->caplen - 20;
	    data = (u_char*)(dev_pkt + 20);
	}
    }
    else if (option == 2) { // hash IP/ARP/RARP payload
	if (instance->hwinfo->link_type == DLT_EN10MB) /* ethernet */ {
	    eth = (struct ether_header *)link_pkt;
	    if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
		iph = (struct iphdr *) (dev_pkt + sizeof(struct ether_header));
		datalen = ntohs(iph->tot_len) - (iph->ihl << 2);
		data = (u_char *) iph + (iph->ihl << 2);
	    }
	    else if (ntohs(eth->ether_type) == ETHERTYPE_ARP
		|| ntohs(eth->ether_type) == ETHERTYPE_REVARP) {
		arph = (struct arphdr *) (dev_pkt + sizeof(struct ether_header));
		datalen = pkt_head->caplen - sizeof(struct ether_header) - sizeof(struct arphdr);
		data = (u_char *) arph + sizeof(struct arphdr);
	    }
	    else {
		datalen = 0;
		data = 0x00;
	    }
	}
	else if (instance->hwinfo->link_type == DLT_CHDLC) { /* CHDLC */
	    if (ntohs(*(uint16_t*)(dev_pkt + 18)) == ETHERTYPE_IP) {
		iph = (struct iphdr *) (dev_pkt + 20);
		datalen = ntohs(iph->tot_len) - (iph->ihl << 2);
		data = (u_char *) iph + (iph->ihl << 2);
	    }
	    else if (ntohs(*(uint16_t*)(dev_pkt + 18)) == ETHERTYPE_ARP
		|| ntohs(*(uint16_t*)(dev_pkt + 18)) == ETHERTYPE_REVARP) {
		arph = (struct arphdr *) (dev_pkt + 20);
		datalen = pkt_head->caplen - 20 - sizeof(struct arphdr);
		data = (u_char *) arph + sizeof(struct arphdr);
	    }
	    else {
		datalen = 0;
		data = 0x00;
	    }
	} else {
	    datalen = 0;
	    data = 0x00;
	}
    }
    else if (option == 3) { // hash TCP/UDP/ICMP payload
	eth = (struct ether_header *)link_pkt;
	if ((instance->hwinfo->link_type == DLT_EN10MB && ntohs(eth->ether_type) == ETHERTYPE_IP)
	  || (instance->hwinfo->link_type == DLT_CHDLC && ntohs(*(uint16_t*)(dev_pkt + 18)) == ETHERTYPE_IP)) {
	    if (instance->hwinfo->link_type == DLT_EN10MB) {
			iph = (struct iphdr *)(dev_pkt + sizeof(struct ether_header));
		} else if (instance->hwinfo->link_type == DLT_CHDLC) {
			iph = (struct iphdr *) (dev_pkt + 20);
	    }

	    switch (iph->protocol) {
		case IPPROTO_TCP:
		    tcph = (struct tcphdr*)((u_char*)iph + (iph->ihl << 2));
		    payload = (u_char*)((u_char*)iph + (iph->ihl << 2) + (tcph->doff * 4));
		    payloadlen = (unsigned int)iph + ntohs(iph->tot_len) - (unsigned int)payload;
		    break;
		case IPPROTO_UDP:
		    udph = (struct udphdr*)((u_char*)iph + (iph->ihl << 2));
		    payload = (u_char *) udph + sizeof(struct udphdr);
		    payloadlen = (unsigned int)iph + ntohs(iph->tot_len) - (unsigned int)payload;
		    break;
		case IPPROTO_ICMP:
		    icmph = (struct icmp*)((u_char*)iph + (iph->ihl << 2));
		    payload = (unsigned char *) icmph + sizeof(struct icmp);
		    payloadlen = (unsigned int)iph + ntohs(iph->tot_len) - (unsigned int)payload;
		    break;
		default:
		    payload = 0x00;
		    payloadlen = 0;
		    break;
	    }
	    datalen = payloadlen;
	    data = payload;
	} else {
	    datalen = 0;
	    data = 0x00;
	}
    } else { //invalid option
	assert(0);
    }

    for (hash = datalen, i = 0; i < datalen; i++) {
	hash += data[i];
    }

    hash = hash % prime;
    ptr = (unsigned int *) (instance->result.data);
    (*ptr) = hash;

    return 1;
}

static mapidflib_function_def_t finfo = {
    "",				//libname
    "HASH",			//name
    "Computes an additive hash over the packets of a flow\n\tReturn value: unsigned int",	//descr
    "i",			//argdescr
    MAPI_DEVICE_ALL,		//devoid
    MAPIRES_SHM,
    sizeof(unsigned int),	//shm size
    0,				//modifies_pkts
    0,				//filters packets
    MAPIOPT_AUTO,		//Optimization
    hash_instance,		//instance
    hash_init,
    hash_process,
    NULL,			// get_result,
    NULL,			//reset,
    NULL,			//cleanup,
    NULL,			//client_init
    NULL,			//client_read_result
    NULL			//client_cleanup
};

mapidflib_function_def_t *hash_get_funct_info();

mapidflib_function_def_t *hash_get_funct_info()
{
    return &finfo;
};
