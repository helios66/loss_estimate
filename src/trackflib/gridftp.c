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
	unsigned int byte_counter;
	unsigned int fin;
	unsigned int ack;
};

struct list{
	struct filters *head;
	struct filters *tail;
};


int isGRIDFTP(mapidflib_function_instance_t *, unsigned char *, int );

struct mapid_ftp {
	struct list **ftplist;
	struct list **cntlist;
};

static int gridftp_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{
	int i=0;

	instance->internal_data = malloc(sizeof(struct mapid_ftp));
	((struct mapid_ftp*)instance->internal_data)->ftplist = (struct list**)malloc(sizeof(struct list*)*HASHTABLESIZE);
	((struct mapid_ftp*)instance->internal_data)->cntlist = (struct list**)malloc(sizeof(struct list*)*HASHTABLESIZE);

	for(i = 0; i < HASHTABLESIZE; i++) {
		((struct mapid_ftp*)instance->internal_data)->ftplist[i] = (struct list*)malloc(sizeof(struct list));
		((struct mapid_ftp*)instance->internal_data)->ftplist[i]->head = NULL;
		((struct mapid_ftp*)instance->internal_data)->ftplist[i]->tail = NULL;
		
		((struct mapid_ftp*)instance->internal_data)->cntlist[i] = (struct list*)malloc(sizeof(struct list));
		((struct mapid_ftp*)instance->internal_data)->cntlist[i]->head = NULL;
		((struct mapid_ftp*)instance->internal_data)->cntlist[i]->tail = NULL;
	}
	return 0;
}	

static int gridftp_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			unsigned char* pkt,
			mapid_pkthdr_t* pkt_head)
{
	struct filters *temp = NULL, *prev = NULL, *new = NULL, *temp2 = NULL;
	struct filters *tmp = NULL, *prv = NULL;
	int len = pkt_head->wlen;
	unsigned char *p = NULL;
	struct timeval ts;

	struct list **ftplist = ((struct mapid_ftp*)instance->internal_data)->ftplist;
	struct list **cntlist = ((struct mapid_ftp*)instance->internal_data)->cntlist;
	uint16_t ethertype;
	struct ether_header *ep = NULL;
	struct pos_header {
		uint16_t af;
		uint16_t cf;
	}	*pp = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	
	unsigned int saddr, daddr;
	
	struct in_addr source, dest;
	struct vlan_802q_header *vlan_header;

	uint16_t sp, dp;

	unsigned int hashval = 0;
	int pkt_color = pkt_head->color;
	
	if(pkt_color != 0 && pkt_color != FTP_COLOR) {
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

	hashval = (saddr + daddr) % HASHTABLESIZE;
	
	if(iph->protocol == 6)	// TCP
	{
		tcph = (struct tcphdr *)p;
		
		sp = ntohs(tcph->source);
		dp = ntohs(tcph->dest);

		p += tcph->doff * 4;

		len -= tcph->doff * 4;
	}
	else
	{
		return 0;
	}

	gettimeofday(&ts, NULL);

	if(sp == 2811 || dp == 2811) {
		for(temp = cntlist[hashval]->head, prev = cntlist[hashval]->head; temp != NULL; prev = temp, temp = temp->next) {
			if((temp->saddr == saddr && temp->daddr == daddr && temp->sp == sp && temp->dp == dp) || 
					(temp->saddr == daddr && temp->daddr == saddr && temp->sp == dp && temp->dp == sp))
			{
				temp->ts = ts;

				if(tcph->fin) {
					temp->fin++;
				}
				if(temp->fin == 2 && tcph->ack) {
					temp->ack++;
				}
				
				if(temp->fin == 2 && temp->ack == 2) {
					if(temp == cntlist[hashval]->head) {
						cntlist[hashval]->head = temp->next;
					}
					else {
						prev->next = temp->next;
					}
					free(temp);
					temp = NULL;
					
					// free other side 
					for(temp = prev; temp != NULL; prev = temp, temp = temp->next) {
						if((temp->saddr == saddr && temp->daddr == daddr && temp->sp == sp && temp->dp == dp) || 
							(temp->saddr == daddr && temp->daddr == saddr && temp->sp == dp && temp->dp == sp)) {
								temp->ts = ts;
								
								if(temp->fin == 2 && temp->ack == 2) {
									if(temp == cntlist[hashval]->head) {
										cntlist[hashval]->head = temp->next;
									}
									else {
										prev->next = temp->next;
									}
								}
						}
					}
					
					free(temp);
					// free same pair from ftplist
					for(tmp = ftplist[hashval]->head, prv = ftplist[hashval]->head; tmp != NULL; prv = tmp, tmp = tmp->next) {
						if((tmp->saddr == saddr && tmp->daddr == daddr) || (tmp->saddr == daddr && tmp->daddr == saddr)) {
							if(tmp == ftplist[hashval]->head) {
								ftplist[hashval]->head = tmp->next;
							}
							else {
								prv->next = tmp->next;
							}
						}
					}
					free(tmp);
				}
				
				pkt_head->color = FTP_COLOR;
				return 1;
			}

			// flow_cleanup
			if(ts.tv_sec - temp->ts.tv_sec > 60) {
				if(temp == cntlist[hashval]->head) {
					cntlist[hashval]->head = temp->next;
				}
				else {
					prev->next = temp->next;	
				}
				temp->next = NULL;
				free(temp);
			}
		}

		if(!tcph->syn) {
			return 1;
		}
		// create new enty for new FTP server
		new = (struct filters*)malloc(sizeof(struct filters));
		
		new->protocol = iph->protocol;
		new->saddr = saddr;
		new->daddr = daddr;
		new->sp = sp;
		new->dp = dp;
		new->fin = 0;
		new->ack = 0;
		new->next = NULL;
#ifdef __TRACKFLIB_LOGGING__
		write_to_log("GRIDFTP", "No string", iph->protocol, source, sp, dest, dp, p, len);
#endif
		for(temp = cntlist[hashval]->head; temp != NULL; temp = temp->next) {
			if(new->protocol == temp->protocol && (
					(new->saddr == temp->saddr && new->daddr == temp->daddr && new->sp == temp->sp && new->dp == temp->dp) 
					||
					(new->daddr == temp->saddr && new->saddr == temp->daddr && new->dp == temp->sp && new->sp == temp->dp)
					)
				)
			{
				pkt_head->color = FTP_COLOR;
				free(new);
				return 1;
			}
		}

		gettimeofday(&(new->ts), NULL);
				
		new->next = cntlist[hashval]->head;
		cntlist[hashval]->head = new;

		pkt_head->color = FTP_COLOR;
		return 1;
	}
	else {
		for(temp = ftplist[hashval]->head, prev = ftplist[hashval]->head; temp != NULL; prev = temp, temp = temp->next) {
			if(temp->protocol == iph->protocol &&
				(
				 (temp->saddr == saddr && temp->daddr == daddr && temp->sp == sp && temp->dp == dp)
				 ||
				 (temp->saddr == daddr && temp->daddr == saddr && temp->sp == dp && temp->dp == sp))
				)
			{
				gettimeofday(&(temp->ts), NULL);
				
				if(iph->protocol == 6 && tcph->fin && tcph->ack) {
					if(temp == ftplist[hashval]->head) {
						ftplist[hashval]->head = temp->next;
					}
					else {
						prev->next = temp->next;
					}
					temp->next = NULL;
					free(temp);

					// find the other direction too
					for(temp = prev; temp != NULL; prev = temp, temp = temp->next) {
						if(temp->protocol == iph->protocol &&	(
							(temp->saddr == saddr && temp->daddr == daddr && temp->sp == sp && temp->dp == dp)
							||
							(temp->saddr == daddr && temp->daddr == saddr && temp->sp == dp && temp->dp == sp))
						)
						{
								if(iph->protocol == 6 && tcph->fin && tcph->ack) {
									if(temp == ftplist[hashval]->head) {
											ftplist[hashval]->head = temp->next;
									}
									else {
											prev->next = temp->next;
									}
									temp->next = NULL;
									free(temp);
								}
						}				
					}
				}
			
				pkt_head->color = FTP_COLOR;
				return 1;
			}
			
			// flow cleanup
			if(ts.tv_sec - temp->ts.tv_sec > 60) {
				if(temp == ftplist[hashval]->head) {
					ftplist[hashval]->head = temp->next;
				}
				else {
					prev->next = temp->next;
				}
				temp->next = NULL;
				free(temp);
			}
		}

		if((sp >= 20000 && sp <= 25000) || (dp >= 20000 && dp <= 25000)) {
			// look if this has a previous control FTP connection
			for(temp = cntlist[hashval]->head, prev = cntlist[hashval]->head; temp != NULL; prev = temp, temp = temp->next) {
				if((temp->saddr == saddr && temp->daddr == daddr) || (temp->saddr == daddr && temp->daddr == saddr)) {
					// new ftp PASV connection
					new = (struct filters*)malloc(sizeof(struct filters));

					new->protocol = iph->protocol;
					new->saddr = saddr;
					new->daddr = daddr;
					new->sp = sp;
					new->dp = dp;
					new->next = NULL;
					new->fin = 0;
					new->ack = 0;
#ifdef __TRACKFLIB_LOGGING__
					write_to_log("GRIDFTP_PASV", "No string", iph->protocol, source, sp, dest, dp, p, len);
#endif
					for(temp2 = ftplist[hashval]->head; temp2 != NULL; temp2 = temp2->next) {
						if(new->protocol == temp2->protocol && (
							(new->saddr == temp2->saddr && new->daddr == temp2->daddr && new->sp == temp2->sp && new->dp == temp2->dp) 
							||
							(new->daddr == temp2->saddr && new->saddr == temp2->daddr && new->dp == temp2->sp && new->sp == temp2->dp)
							)
						)
						{
							pkt_head->color = FTP_COLOR;
							free(new);
							return 1;
						}
					}
					
					gettimeofday(&(new->ts), NULL);
					
					new->next = ftplist[hashval]->head;
					ftplist[hashval]->head = new;
					
					pkt_head->color = FTP_COLOR;
					return 1;
				}
			}
		}
	}

	return 0;
}

static int gridftp_cleanup(mapidflib_function_instance_t *instance) 
{
	struct filters *temp = NULL, *tmp = NULL;
	int i = 0;
	
  if(instance->internal_data != NULL){
	  for(i = 0; i < HASHTABLESIZE; i++) {
		  temp = ((struct mapid_ftp*)instance->internal_data)->ftplist[i]->head;
		  
		  while(temp != NULL) {
			  tmp = temp;
			  temp = temp->next;
			  free(tmp);
		  }

		  free(((struct mapid_ftp*)instance->internal_data)->ftplist[i]);
		
		  temp = ((struct mapid_ftp*)instance->internal_data)->cntlist[i]->head;
		  
		  while(temp != NULL) {
			  tmp = temp;
			  temp = temp->next;
			  free(tmp);
		  }

		  free(((struct mapid_ftp*)instance->internal_data)->cntlist[i]);
	  }
	free(((struct mapid_ftp*)instance->internal_data)->ftplist);
	free(((struct mapid_ftp*)instance->internal_data)->cntlist);
	free(instance->internal_data);
  }
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "TRACK_GRID_FTP",
  "Searches for GRID FTP packets\n",
  "",
  MAPI_DEVICE_ALL,
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_NONE,
  NULL,
  gridftp_init,
 	gridftp_process,
  NULL, //get_result
  NULL, //reset
  gridftp_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* gridftp_get_funct_info();
mapidflib_function_def_t* gridftp_get_funct_info() {
  return &finfo;
};

