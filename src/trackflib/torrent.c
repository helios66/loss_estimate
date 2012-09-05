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
#include "edonkey.h"


struct filters {
	int protocol;
	unsigned int saddr;
	unsigned int daddr;
	uint16_t sp;
	uint16_t dp;
	struct timeval ts;
	struct filters *next;
	unsigned int byte_counter;
};

struct list{
	struct filters *head;
	struct filters *tail;
};

#define TOR_STRINGS_NO 16

char *torrent_strings[TOR_STRINGS_NO]={"BitTorrent protocol","GET /scrape?info_hash=","GET /announce?info_hash=", "d1:rd2:id20:", "d1:ad2:id20:", "User-Agent: Azureus", "/scrape?info_hash=", "BT_PIECE"
						,"BT_REQUEST", "BT_CHOKE", "BT_UNCHOKE", "BT_HAVE", "BT_UNINTERESTED", "BT_INTERESTER", "BT_BITFIELD", "BT_CANCEL"};

int torrent_lens[TOR_STRINGS_NO]={20, 100, 100, 20, 20, 100, 100, 50, 50, 50, 50, 50, 50, 50, 50 , 50};

int isTorrent(mapidflib_function_instance_t *, unsigned char *, unsigned int );

struct mapid_torrent {
#ifndef __WITH_AHO__
	int *shift[TOR_STRINGS_NO];
	int *skip[TOR_STRINGS_NO];
#else
	ACSM_STRUCT2 *acsm;
#endif
	unsigned int search_len[TOR_STRINGS_NO]; 
	struct list **torlist;
};

static int torrent_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{
	int i=0;
#ifdef __WITH_AHO__
	char *p;
#endif
	instance->internal_data = malloc(sizeof(struct mapid_torrent));
	((struct mapid_torrent*)instance->internal_data)->torlist = (struct list**)malloc(sizeof(struct list*)*HASHTABLESIZE);

	for(i = 0; i < HASHTABLESIZE; i++) {
		((struct mapid_torrent*)instance->internal_data)->torlist[i] = (struct list*)malloc(sizeof(struct list));
		((struct mapid_torrent*)instance->internal_data)->torlist[i]->head = NULL;
		((struct mapid_torrent*)instance->internal_data)->torlist[i]->tail = NULL;
	}

#ifndef __WITH_AHO__
	
	for(i=0;i<TOR_STRINGS_NO;i++) {
		((struct mapid_torrent*)instance->internal_data)->shift[i] = make_shift(torrent_strings[i],strlen(torrent_strings[i]));
		((struct mapid_torrent*)instance->internal_data)->skip[i] = make_skip(torrent_strings[i], strlen(torrent_strings[i]));
		((struct mapid_torrent*)instance->internal_data)->search_len[i] = torrent_lens[i];
	}
#else
	((struct mapid_torrent*)instance->internal_data)->acsm = acsmNew2();
	
	if(!(((struct mapid_torrent*)instance->internal_data)->acsm)) {
		return MAPID_MEM_ALLOCATION_ERROR;
	}
	
	for (i = 1; i < TOR_STRINGS_NO; i++) {
		p = torrent_strings[i];
		
	//	int acsmAddPattern2 (ACSM_STRUCT2 * p, unsigned char *pat, int n, int nocase,
	//		int offset, int depth, void * id, int iid) 
		DEBUG_CMD(Debug_Message("torrent_lens[%d] = %d", i, torrent_lens[i]));
		acsmAddPattern2(((struct mapid_torrent*)instance->internal_data)->acsm, p, strlen(p), 1, 0, torrent_lens[i],(void*)p, i);
	}

	acsmCompile2(((struct mapid_torrent*)instance->internal_data)->acsm);

#endif

	return 0;
}	


#ifdef __WITH_AHO__

static int global_index = -1;
static char *found = NULL;

	int torrent_matchFound(void* id, int my_index, MAPI_UNUSED void *data) 
	{
		DEBUG_CMD(Debug_Message("found %s index %d", (char *)id, my_index));
  		global_index = my_index;
		found = (char *)id;

		return my_index;
	}
#endif

int isTorrent(mapidflib_function_instance_t *instance, unsigned char *pkt, unsigned int len)
{
#ifndef __WITH_AHO__
	int i=0;
#else
	global_index = -1;
	found = NULL;
#endif

	if(pkt[0] == 19 && (memcmp(&pkt[1], torrent_strings[0], 19) == 0))
		return 0;

#ifndef __WITH_AHO__
	for(i=1;i<TOR_STRINGS_NO;i++) {
		if(len < strlen(torrent_strings[i]))
				continue;

		if(((struct mapid_torrent*)instance->internal_data)->search_len[i] > len) {
			if(mSearch((char *)(pkt), len, torrent_strings[i], strlen(torrent_strings[i]),
				((struct mapid_torrent *)instance->internal_data)->skip[i],
				((struct mapid_torrent *)instance->internal_data)->shift[i])) {
				return i;
			}
		}
		else {
			if(mSearch((char *)(pkt), ((struct mapid_torrent*)instance->internal_data)->search_len[i], torrent_strings[i], strlen(torrent_strings[i]),
						((struct mapid_torrent *)instance->internal_data)->skip[i],
						((struct mapid_torrent *)instance->internal_data)->shift[i])){
				return i;
			}
		}
	}
#else 

//	int acsmSearch2(ACSM_STRUCT2 * acsm, unsigned char *Tx, int n,
//			int (*Match) (void * id, int index, void *data), void *data) 

	acsmSearch2(((struct mapid_torrent*)instance->internal_data)->acsm, pkt, len, torrent_matchFound, (void *)0);
	
	return global_index;
	

#endif
	return -1;

}

void print_some_bytes(char *packet, int len) 
{
	int i = 0;
	
	for(i = 0; i < 100 && i < len; i++) {
			if(isprint(packet[i])){
				printf("%c", packet[i]);
			}
			else if(packet[i] == '\n') {			
				printf(".");
			}
			else {
				printf(".");
			}
	}
}

static int torrent_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			unsigned char* pkt,
			mapid_pkthdr_t* pkt_head)
{
	struct filters *temp = NULL, *prev = NULL, *new = NULL;
	int len = pkt_head->wlen;
	unsigned char *p = NULL;
	struct timeval ts;

	struct list **torlist = ((struct mapid_torrent*)instance->internal_data)->torlist;
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

	int ip_len = 0, tcp_len = 0, udp_len = 0;

	int pkt_color = pkt_head->color;
	
	if(pkt_color != 0 && pkt_color != TORRENT_COLOR) {
		return 0;
	}

	p = pkt;
/*	
typedef struct flags {
        uint8_t           iface:2;
        uint8_t           vlen:1;
        uint8_t           trunc:1;
        uint8_t           rxerror:1;
        uint8_t           dserror:1;
        uint8_t           reserved:1;
        uint8_t           direction:1;
} flags_t;
typedef struct dag_record {
        uint64_t          ts;
        uint8_t           type;
        flags_t           flags;
        uint16_t          rlen;
        uint16_t          lctr;
        uint16_t          wlen;
        union {
                pos_rec_t       pos;
                eth_rec_t       eth;
                atm_rec_t       atm;
                aal5_rec_t      aal5;
                aal2_rec_t      aal2;
                mc_hdlc_rec_t   mc_hdlc;
                mc_raw_rec_t    mc_raw;
                mc_atm_rec_t    mc_atm;
                mc_aal_rec_t    mc_aal5;
                mc_aal_rec_t    mc_aal2;
                mc_raw_channel_rec_t mc_raw_channel;
        } rec;
} dag_record_t;

typedef struct pos_rec {
        uint32_t          hdlc;
        uint8_t           pload[1];
} pos_rec_t;

typedef struct eth_rec {
        uint8_t           offset;
        uint8_t           pad;

        uint8_t           dst[6];
        uint8_t           src[6];
        uint16_t          etype;

        uint8_t           pload[1];
} eth_rec_t;

typedef struct mc_hdlc_rec {
        uint32_t          mc_header;

        uint8_t           pload[1];
} mc_hdlc_rec_t;
*/
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
	ip_len = (iph->ihl & 0xf) * 4;

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
		tcp_len = tcph->doff * 4;
		
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
		udp_len = sizeof(struct udphdr);

		sp = ntohs(udph->source);
		dp = ntohs(udph->dest);

		p += sizeof(struct udphdr);
		
		if((unsigned int)(p - pkt) == pkt_head->caplen) {
			return 0;
		}

		len -= sizeof(struct udphdr);
	}
	else
	{
		return 0;
	}

	
	/* excluding default traffic from other trackers */
	if(sp == 4662 || dp == 4662) { // eDonkey
		return 0;
	}

	if(sp == 411 || dp == 411) { // DC++
		return 0;
	}
	
	gettimeofday(&ts, NULL);

	for(temp = torlist[hashval]->head, prev = torlist[hashval]->head; temp != NULL; prev = temp, temp = temp->next)
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
				if(temp == torlist[hashval]->head) {
					torlist[hashval]->head = temp->next;
				}
				else {
					prev->next = temp->next;
				}
				temp->next = NULL;
				free(temp);
			}

			temp->byte_counter += pkt_head->caplen;

			if(temp->byte_counter >= 1000000) {
//				printf("%s:%d \n", inet_ntoa(source), sp);
//				printf("%s:%d %u\n", inet_ntoa(dest), dp, temp->byte_counter);
				temp->byte_counter = 0;			
			}
			pkt_head->color = TORRENT_COLOR;
			
			return 1;
		}
	
		// flow cleanup
		if(ts.tv_sec - temp->ts.tv_sec > 60) {
			if(temp == torlist[hashval]->head) {
				torlist[hashval]->head = temp->next;
			}
			else {
				prev->next = temp->next;
			}
			temp->next = NULL;
			free(temp);
		}
	}

	if((i = isTorrent(instance,p,len)) >= 0)
	{
		new = (struct filters*)malloc(sizeof(struct filters));
		
		new->protocol = iph->protocol;
		new->saddr = saddr;
		new->daddr = daddr;
		new->sp = sp;
		new->dp = dp;
		new->byte_counter = 0;
#ifdef __TRACKFLIB_LOGGING__
	#ifndef __WITH_AHO__
		write_to_log("BitTorrent", torrent_strings[i], iph->protocol, source, sp, dest, dp, p, len);
	#else
		if(global_index == -1) {
			write_to_log("BitTorrent", torrent_strings[0], iph->protocol, source, sp, dest, dp, p, len);
		}
		else {
			write_to_log("BitTorrent", found, iph->protocol, source, sp, dest, dp, p, len);
		}
		
	#endif
#endif
		for(temp = torlist[hashval]->head; temp != NULL; temp = temp->next)
		{
			if(new->protocol == temp->protocol && (
					(new->saddr == temp->saddr && new->daddr == temp->daddr && new->sp == temp->sp && new->dp == temp->dp) 
					||
					(new->daddr == temp->saddr && new->saddr == temp->daddr && new->dp == temp->sp && new->sp == temp->dp)
					)
				)
			{
				pkt_head->color = TORRENT_COLOR;
				free(new);
				return 1;
			}
		}

		gettimeofday(&(new->ts), NULL);
				
		new->next = torlist[hashval]->head;
		torlist[hashval]->head = new;

		pkt_head->color = TORRENT_COLOR;

		return 1;
	}
	return 0;
}

static int torrent_cleanup(mapidflib_function_instance_t *instance) 
{
	struct filters *temp = NULL, *tmp = NULL;
	int i = 0;
	
  if(instance->internal_data != NULL){
	  for(i = 0; i < HASHTABLESIZE; i++) {
		  temp = ((struct mapid_torrent*)instance->internal_data)->torlist[i]->head;
		  
		  while(temp != NULL) {
			  tmp = temp;
			  temp = temp->next;
			  free(tmp);
		  }
		  free(((struct mapid_torrent*)instance->internal_data)->torlist[i]);
	  }
#ifndef __WITH_AHO__

        for(i=0;i<TOR_STRINGS_NO;i++) {
                free(((struct mapid_torrent*)instance->internal_data)->shift[i]);
                free(((struct mapid_torrent*)instance->internal_data)->skip[i]);
        }
#else
	  acsmFree2(((struct mapid_torrent*)instance->internal_data)->acsm);
#endif

	free(((struct mapid_torrent*)instance->internal_data)->torlist);
	free(instance->internal_data);
  }
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "TRACK_TORRENT",
  "Searches for BitTorrent packets\n",
  "",
  MAPI_DEVICE_ALL,
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_NONE,
  NULL,
  torrent_init,
  torrent_process,
  NULL, //get_result
  NULL, //reset
  torrent_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* torrent_get_funct_info();
mapidflib_function_def_t* torrent_get_funct_info() {
  return &finfo;
};

