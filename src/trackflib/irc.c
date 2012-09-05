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

#define IRC_HASHTABLESIZE 1024
#define STRING_NUM 5

int isIRC(mapidflib_function_instance_t *instance, unsigned char *pkt, unsigned int len);

char *irc_strings[STRING_NUM]={"PRIVMSG ", "NOTICE ", " :DOWN// ", " :EFTP// ", "ACTION"};

int irc_string_len[STRING_NUM] = {0};

struct mapid_irc {
	int *shift[STRING_NUM];
	int *skip[STRING_NUM];
	struct list **irclist;
};

static int irc_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{
	int i=0;	
	
	instance->internal_data = malloc(sizeof(struct mapid_irc));
	((struct mapid_irc*)instance->internal_data)->irclist = (struct list**)malloc(sizeof(struct list*)*IRC_HASHTABLESIZE);
	memset(((struct mapid_irc*)instance->internal_data)->irclist, 0, (sizeof(struct list*)*IRC_HASHTABLESIZE));
	for(i = 0; i < IRC_HASHTABLESIZE; i++) {
		((struct mapid_irc*)instance->internal_data)->irclist[i] = (struct list*)malloc(sizeof(struct list));
		((struct mapid_irc*)instance->internal_data)->irclist[i]->head = NULL;
		((struct mapid_irc*)instance->internal_data)->irclist[i]->tail = NULL;
	}
	for(i=0;i<STRING_NUM;i++) {
		((struct mapid_irc*)instance->internal_data)->shift[i] = make_shift(irc_strings[i],strlen(irc_strings[i]));
		((struct mapid_irc*)instance->internal_data)->skip[i] = make_skip(irc_strings[i], strlen(irc_strings[i]));
	}

	return 0;
}	

int isIRC(mapidflib_function_instance_t *instance, unsigned char *pkt, unsigned int len)
{
	int i=0;

	for(i=0;i<STRING_NUM;i++) {
		if(len < strlen(irc_strings[i]))
				continue;
		
		if(len >= 100) {
			if(mSearch((char *)(pkt), 100, irc_strings[i], strlen(irc_strings[i]),
						((struct mapid_irc *)instance->internal_data)->skip[i],
						((struct mapid_irc *)instance->internal_data)->shift[i]))
			{
				return i;
			}
		}
		else {
			if(mSearch((char *)(pkt), len, irc_strings[i], strlen(irc_strings[i]),
						((struct mapid_irc *)instance->internal_data)->skip[i],
						((struct mapid_irc *)instance->internal_data)->shift[i]))
			{
				return i;
			}
		}
	}
	return -1;

}

static int irc_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			unsigned char* pkt,
			mapid_pkthdr_t* pkt_head)
{
	struct filters *temp = NULL, *prev = NULL, *new = NULL;
	int len = pkt_head->caplen;
	unsigned char *p = NULL;
	struct timeval ts;

	struct list **irclist = ((struct mapid_irc*)instance->internal_data)->irclist;
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
	
	source.s_addr = (unsigned long int)iph->saddr ;
	dest.s_addr = (unsigned long int)iph->daddr;

	p += iph->ihl * 4;
	len -= iph->ihl * 4;

	hashval = (saddr + daddr) % IRC_HASHTABLESIZE;

	if(iph->protocol == 6)	// TCP
	{
		tcph = (struct tcphdr *)p;
		
		sp = ntohs(tcph->source);
		dp = ntohs(tcph->dest);

		p += tcph->doff * 4;
		len -= tcph->doff * 4;

		if((unsigned int)(p - pkt) == pkt_head->caplen) {
			return 0;
		}
	}
	else if(iph->protocol == 17)	// UDP
	{
		udph = (struct udphdr *)p;

		sp = ntohs(udph->source);
		dp = ntohs(udph->dest);

		p += sizeof(struct udphdr);
		len -= sizeof(struct udphdr);

		if((unsigned int)(p - pkt) == pkt_head->caplen) {
			return 0;
		}
	}
	else
	{
		return 0;
	}

	gettimeofday(&ts, NULL);
	
	for(temp = irclist[hashval]->head, prev = irclist[hashval]->head; temp != NULL; prev = temp, temp = temp->next)
	{
			if(temp->protocol == iph->protocol &&
					(
					(temp->saddr == saddr && temp->daddr == daddr && temp->sp == sp && temp->dp == dp)
					||
					(temp->saddr == daddr && temp->daddr == saddr && temp->sp == dp && temp->dp == sp))
			  )
			{
				gettimeofday(&(temp->ts), NULL);

				if(iph->protocol == 6 && tcph->fin) {
					if(temp == irclist[hashval]->head){
						irclist[hashval]->head = temp->next;
					}
					else {
						prev->next = temp->next;
					}
					temp->next = NULL;
					free(temp);
				}
				
				return 1;
			}
			
			if(ts.tv_sec - temp->ts.tv_sec > 60) {
				if(temp == irclist[hashval]->head){
					irclist[hashval]->head = temp->next;
				}
				else {
					prev->next = temp->next;
				}
				temp->next = NULL;
				free(temp);
			}
	}


	if((i = isIRC(instance,pkt,len)) >= 0)
	{
#ifdef __TRACKFLIB_LOGGING__
		unsigned char *p_b = p;
#endif
		new = (struct filters*)malloc(sizeof(struct filters));

		new->protocol = iph->protocol;
		new->saddr = saddr;
		new->daddr = daddr;
		new->sp = sp;
		new->dp = dp;
#ifdef __TRACKFLIB_LOGGING__
		write_to_log("IRC", irc_strings[i], iph->protocol, source, sp, dest, dp, p_b, len);
#endif

		for(temp = irclist[hashval]->head; temp != NULL; temp = temp->next)
		{
			if(new->protocol == temp->protocol && (
					(new->saddr == temp->saddr && new->daddr == temp->daddr && new->sp == temp->sp && new->dp == temp->dp) 
					||
					(new->daddr == temp->saddr && new->saddr == temp->daddr && new->dp == temp->sp && new->sp == temp->dp)
					)
				)
			{
				return 1;
			}
		}

		gettimeofday(&(new->ts), NULL);
		
		new->next = irclist[hashval]->head;
		irclist[hashval]->head = new;

		return 1;
	}

	return 0;
}

static int irc_cleanup(mapidflib_function_instance_t *instance) 
{
	struct filters *temp = NULL, *tmp = NULL;
	int i = 0;

  if(instance->internal_data != NULL){
	  for(i = 0; i < IRC_HASHTABLESIZE; i++) {
		  temp = ((struct mapid_irc*)instance->internal_data)->irclist[i]->head;
		  
		  while(temp != NULL) {
			  tmp = temp;
			  temp = temp->next;
			  free(tmp);
		  }
	  }
	free(((struct mapid_irc*)instance->internal_data)->irclist);
	free(instance->internal_data);
  }
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "TRACK_IRC",
  "Searches for Internet Relay Chat packets\n",
  "",
  MAPI_DEVICE_ALL,
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_NONE,
  NULL,
  irc_init,
  irc_process,
  NULL, //get_result
  NULL, //reset
  irc_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* irc_get_funct_info();
mapidflib_function_def_t* irc_get_funct_info() {
  return &finfo;
};

