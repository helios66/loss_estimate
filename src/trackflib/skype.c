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
#include <netdb.h>
#include <sys/time.h>
#include <time.h>

#include "log.h"
#include "trackflib.h"
#include "mapi_errors.h"

struct filters {
	int protocol;
	unsigned int addr;
	uint16_t port;
	struct timeval ts;
	struct filters *next;
	struct port_list **port_usage_list;
	struct port_usage *top_port;
};

struct port_usage {
	uint16_t port;
	unsigned long long pkts;
	unsigned long long bytes;
	struct port_usage *next;
};

struct port_list {
	struct port_usage *head;
	struct port_usage *tail;
};

struct list{
	struct filters *head;
	struct filters *tail;
};

#define SKYPE_UI "ui.skype.com"

int isSkype(mapidflib_function_instance_t *, unsigned char *, int );

struct mapid_skype{
	char **skype_host_addrs;
	struct list **skypelist;
	struct list **cntlist;
};

static int trackskype_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{
	int i=0;
	struct hostent* hosts = NULL;

	instance->internal_data = malloc(sizeof(struct mapid_skype));
	((struct mapid_skype*)instance->internal_data)->skypelist = (struct list**)malloc(sizeof(struct list*)*HASHTABLESIZE);
	if(((struct mapid_skype*)instance->internal_data)->skypelist == NULL) {
		return MAPID_MEM_ALLOCATION_ERROR;
	}
	((struct mapid_skype*)instance->internal_data)->cntlist = (struct list**)malloc(sizeof(struct list*)*HASHTABLESIZE);
	if(((struct mapid_skype*)instance->internal_data)->cntlist == NULL) {
		return MAPID_MEM_ALLOCATION_ERROR;
	}
		
	for(i = 0; i < HASHTABLESIZE; i++) {
		((struct mapid_skype*)instance->internal_data)->skypelist[i] = (struct list*)malloc(sizeof(struct list));
		if(((struct mapid_skype*)instance->internal_data)->skypelist[i] == NULL) {
			return MAPID_MEM_ALLOCATION_ERROR;
		}
		((struct mapid_skype*)instance->internal_data)->skypelist[i]->head = NULL;
		((struct mapid_skype*)instance->internal_data)->skypelist[i]->tail = NULL;
		
		((struct mapid_skype*)instance->internal_data)->cntlist[i] = (struct list*)malloc(sizeof(struct list));
		if(((struct mapid_skype*)instance->internal_data)->cntlist[i] == NULL) {
			return MAPID_MEM_ALLOCATION_ERROR;
		}
		((struct mapid_skype*)instance->internal_data)->cntlist[i]->head = NULL;
		((struct mapid_skype*)instance->internal_data)->cntlist[i]->tail = NULL;
	}
	
	if((hosts = gethostbyname(SKYPE_UI)) != NULL) {
		((struct mapid_skype*)instance->internal_data)->skype_host_addrs = hosts->h_addr_list;
	}
	
	return 0;
}	

int add_port_usage(struct filters *temp, uint16_t port, struct timeval ts) 
{
	int i = 0;
	
	struct port_usage *tmp = NULL, *new = NULL;
	unsigned int hashval = port % HASHTABLESIZE;

	if(temp->port_usage_list == NULL) {
		temp->port_usage_list = (struct port_list**)malloc(sizeof(struct port_list*)*HASHTABLESIZE);
		if(temp->port_usage_list == NULL) {
			DEBUG_CMD(Debug_Message("could not alloc temp->port_usage_list"));
		}
		
		for(i = 0; i < HASHTABLESIZE; i++) {
			temp->port_usage_list[i] = (struct port_list*)malloc(sizeof(struct port_list));
			if(temp->port_usage_list[i] == NULL) {
				DEBUG_CMD(Debug_Message("Could not alloc temp->port_usage_list[%d]", i));
			}
			temp->port_usage_list[i]->head = NULL;
			temp->port_usage_list[i]->tail = NULL;
		}
	}

	for(tmp = temp->port_usage_list[hashval]->head; tmp != NULL; tmp = tmp->next) {
		if(tmp->port == port) {
			tmp->pkts++;

			if(temp->top_port == NULL) {
				temp->top_port = (struct port_usage*)malloc(sizeof(struct port_usage));
				temp->top_port->port = 0;
				temp->top_port->pkts = 0;
				if(temp->top_port == NULL) {
					DEBUG_CMD(Debug_Message("Could not alloc temp->top_port"));
				}
				temp->top_port->port = tmp->port;
				temp->top_port->pkts = tmp->pkts;
			}
			else {
				if(tmp->pkts > temp->top_port->pkts) {
					temp->top_port->pkts = tmp->pkts;
				}
			}

			if((ts.tv_sec - temp->ts.tv_sec) >= 10) {
					DEBUG_CMD(Debug_Message("%ld", ts.tv_sec - temp->ts.tv_sec));
					return 2;
			}
			return 1;
		}
	}

	new = (struct port_usage*)malloc(sizeof(struct port_usage));
	if(new == NULL) {
		DEBUG_CMD(Debug_Message("could not alloc new"));
	}
	new->port = port;
	new->pkts = 1;
	new->next = NULL;

	if(temp->port_usage_list[hashval] == NULL) {
		temp->port_usage_list[hashval]->head = new;
	}
	else {
		new->next =  temp->port_usage_list[hashval]->head;
		temp->port_usage_list[hashval]->head = new;
	}

	if(temp->top_port == NULL) {
		temp->top_port = (struct port_usage*)malloc(sizeof(struct port_usage));
		if(temp->top_port == NULL) {
			DEBUG_CMD(Debug_Message("Could not alloc temp->top_port"));
		}
		temp->top_port->port = new->port;
		temp->top_port->pkts = new->pkts;
	}

	if((ts.tv_sec - temp->ts.tv_sec) >= 10) {
		DEBUG_CMD(Debug_Message("%ld", ts.tv_sec - temp->ts.tv_sec));
		return 2;
	}

	return 1;
}

int clean_port_list(struct filters *to_clean) 
{
		struct port_usage *tmp = NULL;
		unsigned int i = 0;
			
		// cleaning port counter status
		for(i = 0; i < HASHTABLESIZE; i++) {
				for(tmp = to_clean->port_usage_list[i]->head; tmp != NULL; tmp = tmp->next) {
						to_clean->port_usage_list[i]->head = tmp->next;
						free(tmp);
				}
			
			free(to_clean->port_usage_list[i]);
				to_clean->port_usage_list[i] = NULL;
		}
		free(to_clean->port_usage_list);
		to_clean->port_usage_list = NULL;
	
		return 1;
						
}
int add_to_ui_hash(mapidflib_function_instance_t *instance, int protocol, unsigned int addr, struct timeval ts) {
	unsigned int hashval = htonl(addr)%HASHTABLESIZE;
	struct filters *temp = NULL, *new = NULL;
	struct list **cntlist = ((struct mapid_skype*)instance->internal_data)->cntlist;


	for(temp = cntlist[hashval]->head; temp != NULL; temp = temp->next) {
		if((addr == temp->addr)) {
			//printf("already in\n");
			return 1;
		}
	}
	
	new = (struct filters *)malloc(sizeof(struct filters));

	if(new == NULL) {
		DEBUG_CMD(Debug_Message("ERROR could not allocate memory"));
	}

	new->protocol = protocol;
	new->addr = addr;
	new->ts = ts;
	new->port = 0;
	new->next = NULL;
	new->port_usage_list = NULL;
	new->top_port = NULL;
	

//	gettimeofday(&(new->ts), NULL);
	
	new->next = cntlist[hashval]->head;
	cntlist[hashval]->head = new;
	
	return 1;
}

static int trackskype_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			unsigned char* pkt,
			mapid_pkthdr_t* pkt_head)
{
	struct filters *temp = NULL, *prev = NULL;
	int len = pkt_head->wlen;
	unsigned char *p = NULL;
	struct timeval ts;

	struct list **skypelist = ((struct mapid_skype*)instance->internal_data)->skypelist;
	struct list **cntlist = ((struct mapid_skype*)instance->internal_data)->cntlist;
	uint16_t ethertype;
	struct ether_header *ep = NULL;
	struct pos_header {
		uint16_t af;
		uint16_t cf;
	}	*pp = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;	
	unsigned int saddr, daddr;
	
	struct in_addr source, dest;
	struct vlan_802q_header *vlan_header;

	uint16_t sp, dp;

	unsigned int hashval = 0, skype_hashval = 0;

	int i = 0;
	int udp_len = 0;
	int ret = 0;

	int pkt_color = pkt_head->color;

	if(pkt_color != 0 && pkt_color != SKYPE_COLOR) {
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

	source.s_addr = (unsigned long int)iph->saddr ;
	dest.s_addr = (unsigned long int)iph->daddr;

	p += iph->ihl * 4;
	len -= iph->ihl *4;

	
	if(iph->protocol == 6)	// TCP
	{
		tcph = (struct tcphdr *)p;
		
		sp = ntohs(tcph->source);
		dp = ntohs(tcph->dest);

		p += tcph->doff * 4;

		len -= tcph->doff * 4;
	}
	else if(iph->protocol == 17) {	// UDP
			udph = (struct udphdr *)p;
			udp_len = sizeof(struct udphdr);

			sp = ntohs(udph->source);
			dp = ntohs(udph->dest);

			p += sizeof(struct udphdr);

			len -= sizeof(struct udphdr);
	}
	else
	{
		return 0;
	}

	//gettimeofday(&ts, NULL);
	ts.tv_sec = pkt_head->ts >> 32;

	/*
	 *	First look for already found skype adrress/port pairs
	 */
	
	hashval = (htonl(saddr)*sp) % HASHTABLESIZE;

	temp = skypelist[hashval]->head;

	for(temp = skypelist[hashval]->head, prev = skypelist[hashval]->head; temp != NULL; prev = temp, temp = temp->next) {
		if(((temp->addr == saddr && temp->port == sp) || (temp->addr == daddr && temp->port == dp))) {
//			gettimeofday(&(temp->ts), NULL);
			temp->ts = ts;
			pkt_head->color = SKYPE_COLOR;
			return 1;
		}
		
		// flow cleanup
		if(ts.tv_sec - temp->ts.tv_sec > 600) {
			if(temp == skypelist[hashval]->head) {
				skypelist[hashval]->head = temp->next;
			}
			else {
				prev->next = temp->next;
			}
			temp->next = NULL;
			free(temp);
			temp = prev;
		}	
	}

	hashval = (htonl(daddr)*dp) % HASHTABLESIZE;

	for(temp = skypelist[hashval]->head, prev = skypelist[hashval]->head; temp != NULL; prev = temp, temp = temp->next) {
		if(((temp->addr == saddr && temp->port == sp) || (temp->addr == daddr && temp->port == dp))) {
//			gettimeofday(&(temp->ts), NULL);
			temp->ts = ts;
			pkt_head->color = SKYPE_COLOR;
			return 1;
		}
		
		// flow cleanup
		if(ts.tv_sec - temp->ts.tv_sec > 600) {
			if(temp == skypelist[hashval]->head) {
				skypelist[hashval]->head = temp->next;
			}
			else {
				prev->next = temp->next;
			}
			temp->next = NULL;
			free(temp);
			temp = prev;
		}	
	}

	// not an already skype machine
	// looking if it has talk with the skype UI and we are on the port measuring process

//	printf("source address %s %d-> ", inet_ntoa(source), sp);
//	printf("\tadding address %s %d\n", inet_ntoa(dest), dp);

	hashval = (htonl(saddr)) % HASHTABLESIZE;

	if(iph->protocol == 17) {
		for(temp = cntlist[hashval]->head, prev = cntlist[hashval]->head; temp != NULL; prev = temp, temp = temp->next) {
			if((temp->addr == saddr)) {
				//printf("----adding usage for port %d\n", sp);
				ret = add_port_usage(temp, sp, ts);
				
				if(ret == 2) {
					// found a skype IP/port pair and adding it to list
					//printf("found IP/port pair with top port %d\n", temp->top_port->port);
					temp->port = temp->top_port->port;
					clean_port_list(temp);
					
					// remove form cntlist
					if(temp == cntlist[hashval]->head) {
						cntlist[hashval]->head = temp->next;
					}
					else {
						prev->next = temp->next;
					}
					
					// adding skype IP/port pair to hashtable skypelist
					skype_hashval = (htonl(saddr)*sp) % HASHTABLESIZE;
	//				gettimeofday(&(temp->ts), NULL);
					temp->ts = ts;
					temp->next = skypelist[skype_hashval]->head;
					skypelist[skype_hashval]->head = temp;

					//printf("Found Skype port\n");
#ifdef __TRACKFLIB_LOGGING__
					write_to_log("Skype", "Found_Skype_port", iph->protocol, source, temp->top_port->port, 0, 0, p_b, len);
#endif
					free(temp->top_port);
					temp->top_port = NULL;

					pkt_head->color = SKYPE_COLOR;
					return 1;
				}
			}
			
			if(ts.tv_sec - temp->ts.tv_sec > 20) { 
				//printf("removing data from cntlist\n");
				if(temp == cntlist[hashval]->head) {
					cntlist[hashval]->head = temp->next;
				}
				else {
					prev->next = temp->next;
				}
				temp->next = NULL;
				free(temp);
				temp = prev;
			}
		}
	}

	hashval = (htonl(daddr)) % HASHTABLESIZE;
	
	if(iph->protocol == 17) {
		for(temp = cntlist[hashval]->head, prev = cntlist[hashval]->head; temp != NULL; prev = temp, temp = temp->next) {
			if((temp->addr == daddr)) {
				ret = add_port_usage(temp, dp, ts);
				//printf("adding usage for port %d\n", dp);
				
				if(ret == 2) {
					// found a skype IP/port pair and adding it to list
					//printf("found IP/port pair with top port %d\n", temp->top_port->port);
					temp->port = temp->top_port->port;
					clean_port_list(temp);
					
					// remove form cntlist
					if(temp == cntlist[hashval]->head) {
						cntlist[hashval]->head = temp->next;
					}
					else {
						prev->next = temp->next;
					}
					
					// adding skype IP/port pair to hashtable skypelist
					skype_hashval = (htonl(daddr)*dp) % HASHTABLESIZE;
//					gettimeofday(&(temp->ts), NULL);
					temp->ts = ts;
					temp->next = skypelist[skype_hashval]->head;
					skypelist[skype_hashval]->head = temp;


#ifdef __TRACKFLIB_LOGGING__
					write_to_log("Skype", "Found_Skype_port", iph->protocol, source, temp->top_port->port, 0, 0, p_b, len);
#endif
					free(temp->top_port);
					temp->top_port = NULL;

					pkt_head->color = SKYPE_COLOR;
					return 1;
				}
			}
			
			if(ts.tv_sec - temp->ts.tv_sec > 20) { 
				//printf("removing port after 10 secs daddr\n");
				if(temp == cntlist[hashval]->head) {
					cntlist[hashval]->head = temp->next;
				}
				else {
					prev->next = temp->next;
				}
				temp->next = NULL;
				free(temp);
				temp = prev;
			}
		}
	}

	// neither that.
	// we are now looking if we have a conversation with the skype ui
	for(i = 0; ((((struct mapid_skype*)instance->internal_data)->skype_host_addrs[i])) != NULL; i++) {
		if(source.s_addr == (*((struct in_addr *)((struct mapid_skype*)instance->internal_data)->skype_host_addrs[i])).s_addr) {
			// found traffic from skype ui
			add_to_ui_hash(instance, iph->protocol, daddr, ts);
			//printf("\tadding address %s\n", inet_ntoa(dest));
#ifdef __TRACKFLIB_LOGGING__
			write_to_log("Skype", "Host_Contacted_with_ui_skype_com", iph->protocol, source, sp, dest, dp, p_b, len);
#endif
			pkt_head->color = SKYPE_COLOR;
			return 1;
		}
		else if(dest.s_addr == (*((struct in_addr *)((struct mapid_skype*)instance->internal_data)->skype_host_addrs[i])).s_addr) {
			// found traffic to skype ui
			add_to_ui_hash(instance, iph->protocol, saddr, ts);
			//printf("\tadding address %s\n", inet_ntoa(source));
#ifdef __TRACKFLIB_LOGGING__
			write_to_log("Skype", "Host_Contacted_with_ui_skype_com", iph->protocol, source, sp, dest, dp, p_b, len);
#endif

			pkt_head->color = SKYPE_COLOR;
			return 1;
		}
	}

	return 0;
}

static int trackskype_cleanup(mapidflib_function_instance_t *instance) 
{
	struct filters *temp = NULL, *tmp = NULL;
	int i = 0;
	
  if(instance->internal_data != NULL){
	  for(i = 0; i < HASHTABLESIZE; i++) {
		  temp = ((struct mapid_skype*)instance->internal_data)->skypelist[i]->head;
		  
		  while(temp != NULL) {
			  tmp = temp;
			  temp = temp->next;
			  free(tmp);
			  tmp = NULL;
		  }

		
		  temp = ((struct mapid_skype*)instance->internal_data)->cntlist[i]->head;
		  
		  while(temp != NULL) {
			  tmp = temp;
			  temp = temp->next;
			  free(tmp);
			  tmp = NULL;
		  }
	  }
	free(((struct mapid_skype*)instance->internal_data)->skypelist);
	free(((struct mapid_skype*)instance->internal_data)->cntlist);
	free(instance->internal_data);
  }
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "TRACK_SKYPE",
  "Searches for SKYPE packets\n",
  "",
  MAPI_DEVICE_ALL,
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_NONE,
  NULL,
  trackskype_init,
  trackskype_process,
  NULL, //get_result
  NULL, //reset
  trackskype_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* trackskype_get_funct_info();
mapidflib_function_def_t* trackskype_get_funct_info() {
  return &finfo;
};

