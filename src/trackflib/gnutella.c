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
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "log.h"
#include "trackflib.h"

struct filters {
	int protocol;
	unsigned int saddr;
	unsigned int daddr;
	uint16_t sp;
	uint16_t dp;
	struct timeval ts;
	struct filters *next;
};

struct list{
	struct filters *head;
	struct filters *tail;
};

#define GNUTELLA_STRING_NO 4

char *gnutella_strings[GNUTELLA_STRING_NO]={"GET /uri-res/N2R?urn:sha1:","GNUTELLA CONNECT/","GNUTELLA/", "Server: LimeWire/"};//,"GET /get/"};

struct mapid_gnutella {
#ifndef __WITH_AHO__
	int *shift[GNUTELLA_STRING_NO];
	int *skip[GNUTELLA_STRING_NO];
#else
	ACSM_STRUCT2 *acsm;
#endif 
	struct list **gnulist;
};

int isGnutella(mapidflib_function_instance_t *,  unsigned char *, unsigned int );

static int gnutella_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{
	int i=0;
#ifdef __WITH_AHO__
	char *p;
#endif

	instance->internal_data = malloc(sizeof(struct mapid_gnutella));
	((struct mapid_gnutella*)instance->internal_data)->gnulist = (struct list**)malloc(sizeof(struct list *)*HASHTABLESIZE);
	memset(((struct mapid_gnutella*)instance->internal_data)->gnulist, 0, (sizeof(struct list*)*HASHTABLESIZE));
	for(i = 0; i < HASHTABLESIZE; i ++) {
		((struct mapid_gnutella*)instance->internal_data)->gnulist[i] = (struct list*)malloc(sizeof(struct list));
		((struct mapid_gnutella*)instance->internal_data)->gnulist[i]->head = NULL;
		((struct mapid_gnutella*)instance->internal_data)->gnulist[i]->tail = NULL;
	}
#ifndef __WITH_AHO__
	for(i=0;i<GNUTELLA_STRING_NO;i++) {
		((struct mapid_gnutella*)instance->internal_data)->shift[i] = make_shift(gnutella_strings[i],strlen(gnutella_strings[i]));
		((struct mapid_gnutella*)instance->internal_data)->skip[i] = make_skip(gnutella_strings[i], strlen(gnutella_strings[i]));
	}
#else 
	((struct mapid_gnutella*)instance->internal_data)->acsm = acsmNew2();

	if(!(((struct mapid_gnutella*)instance->internal_data)->acsm)) {
		return MAPID_MEM_ALLOCATION_ERROR;
	}
	for(i = 0; i < GNUTELLA_STRING_NO; i++) {
		p = gnutella_strings[i];

		acsmAddPattern2(((struct mapid_gnutella*)instance->internal_data)->acsm, p, strlen(p), 1, 0, 100,(void*)p, i);
	}

	acsmCompile2(((struct mapid_gnutella*)instance->internal_data)->acsm);
#endif
	return 0;
}	

#ifdef __WITH_AHO__

static int global_index = -1;
static char *found = NULL;

	int gnutella_matchFound(void* id, int my_index, MAPI_UNUSED void *data) 
	{
  		global_index = my_index;
		found = (char *)id;

		return my_index;
	}
#endif

int isGnutella(mapidflib_function_instance_t *instance, unsigned char *pkt, unsigned int len)
{
#ifndef __WITH_AHO__
	int i=0;

	for(i=0;i<GNUTELLA_STRING_NO;i++) {
		if(len < strlen(gnutella_strings[i]))
				continue;

		if(len < 100) {
			if(mSearch((char *)(pkt), len, gnutella_strings[i], strlen(gnutella_strings[i]),
				((struct mapid_gnutella *)instance->internal_data)->skip[i],
				((struct mapid_gnutella *)instance->internal_data)->shift[i])) {
				return i;
			}
		}
		else {
			if(mSearch((char *)(pkt), 100, gnutella_strings[i], strlen(gnutella_strings[i]),
				((struct mapid_gnutella *)instance->internal_data)->skip[i],
				((struct mapid_gnutella *)instance->internal_data)->shift[i])){
				return i;
			}
		}
	}

#else
	global_index = -1;
	found = NULL;

	acsmSearch2(((struct mapid_gnutella*)instance->internal_data)->acsm, pkt, len, gnutella_matchFound, (void *)0);
	
	return global_index;

#endif
	
	return -1;

}

static int gnutella_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED  unsigned char* dev_pkt,
			 unsigned char* pkt,
			mapid_pkthdr_t* pkt_head)
{
	struct filters *temp = NULL, *prev = NULL, *new = NULL;
	int len = pkt_head->caplen;
	 unsigned char *p = NULL;
	struct timeval ts;

	struct list **gnulist = ((struct mapid_gnutella*)instance->internal_data)->gnulist;
	uint16_t ethertype;
	struct ether_header *ep = NULL;
	struct pos_header {
		uint16_t af;
		uint16_t cf;
	}	*pp = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	
	struct vlan_802q_header *vlan_header;

	unsigned int saddr, daddr;
	struct in_addr source, dest;

	uint16_t sp, dp;

	unsigned int hashval = 0;
	int i = 0;

	int pkt_color = pkt_head->color;

	if(pkt_color != 0 && pkt_color != GNUTELLA_COLOR) {
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

	hashval = (saddr + daddr) % HASHTABLESIZE;

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
	else if(iph->protocol == 17)	// UDP
	{
		udph = (struct udphdr *)p;

		sp = ntohs(udph->source);
		dp = ntohs(udph->dest);

		p += sizeof(struct udphdr);
		
		if((unsigned int)(p -pkt) == pkt_head->caplen) {
			return 0;
		}
		len -= sizeof(struct udphdr);
	}
	else
	{
		return 0;
	}

	gettimeofday(&ts, NULL);

	for(temp = gnulist[hashval]->head, prev = gnulist[hashval]->head; temp != NULL; prev = temp, temp = temp->next)
	{
		if(temp->protocol == iph->protocol &&
				(
				 (temp->saddr == saddr && temp->daddr == daddr && temp->sp == sp && temp->dp == dp)
				 ||
				 (temp->saddr == daddr && temp->daddr == saddr && temp->sp == dp && temp->dp == sp))
				)
		{
				gettimeofday(&(temp->ts), NULL);

				if(iph->protocol == 6 && tcph->fin)	{
					if(temp == gnulist[hashval]->head) {
						gnulist[hashval]->head = temp->next;
					}
					else {
						prev->next = temp->next;
					}
					temp->next = NULL;
					free(temp);
				}
					
			pkt_head->color = GNUTELLA_COLOR;
			return 1;
		}
		
		if(ts.tv_sec - temp->ts.tv_sec > 60) {
			if(temp == gnulist[hashval]->head) {
				gnulist[hashval]->head = temp->next;
			}
			else {
				prev->next = temp->next;
			}
			temp->next = NULL;
			free(temp);
		}
	}

	if((i = isGnutella(instance,pkt,len)) >= 0)
	{
		new = (struct filters*)malloc(sizeof(struct filters));
		if(new == NULL) {
			DEBUG_CMD(Debug_Message("new = NULL (malloc failed)"));
		}

		new->protocol = iph->protocol;
		new->saddr = saddr;
		new->daddr = daddr;
		new->sp = sp;
		new->dp = dp;

#ifdef __TRACKFLIB_LOGGING__
	#ifndef __WITH_AHO__
		write_to_log("GNUTELLA", gnutella_strings[i], iph->protocol, source, sp, dest, dp, pkt, len); 
	#else
		write_to_log("GNUTELLA", found, iph->protocol, source, sp, dest, dp, pkt, len); 
	#endif
#endif
		for(temp = gnulist[hashval]->head; temp != NULL; temp = temp->next)
		{
			if(new->protocol == temp->protocol && (
					(new->saddr == temp->saddr && new->daddr == temp->daddr && new->sp == temp->sp && new->dp == temp->dp) 
					||
					(new->daddr == temp->saddr && new->saddr == temp->daddr && new->dp == temp->sp && new->sp == temp->dp)
					)
				)
			{
				pkt_head->color = GNUTELLA_COLOR;
				return 1;
			}
		}

		gettimeofday(&(new->ts), NULL);

		new->next = gnulist[hashval]->head;
		gnulist[hashval]->head = new;
	
		pkt_head->color = GNUTELLA_COLOR;
		return 1;
	}

	return 0;
}

static int gnutella_cleanup(mapidflib_function_instance_t *instance) 
{
	struct filters *temp = NULL, *tmp = NULL;
	int i = 0;

  if(instance->internal_data != NULL){

	  for(i = 0; i < HASHTABLESIZE; i++) {
		  temp = ((struct mapid_gnutella*)instance->internal_data)->gnulist[i]->head;
		  
		  while(temp != NULL) {
			  tmp = temp;
			  temp = temp->next;
			  free(tmp);
		  }
		  free(((struct mapid_gnutella*)instance->internal_data)->gnulist[i]);
	  }
#ifndef __WITH_AHO__
        for(i=0;i<GNUTELLA_STRING_NO;i++) {
                free(((struct mapid_gnutella*)instance->internal_data)->shift[i]);
                free(((struct mapid_gnutella*)instance->internal_data)->skip[i]);
        }
#else
        acsmFree2(((struct mapid_gnutella*)instance->internal_data)->acsm);
#endif

	free(((struct mapid_gnutella*)instance->internal_data)->gnulist);
	free(instance->internal_data);
  }
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "TRACK_GNUTELLA",
  "Searches for Gnutella packets\n",
  "",
  MAPI_DEVICE_ALL,
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_NONE,
  NULL,
  gnutella_init,
  gnutella_process,
  NULL, //get_result
  NULL, //reset
  gnutella_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* gnutella_get_funct_info();
mapidflib_function_def_t* gnutella_get_funct_info() {
  return &finfo;
};

