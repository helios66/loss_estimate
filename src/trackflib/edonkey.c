#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <unistd.h>
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
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include "edonkey.h"
#include "log.h"
#include "trackflib.h"

struct filters {
	int protocol;
	unsigned int saddr;
	unsigned int daddr;
	uint16_t sp;
	uint16_t dp;
	struct timeval last_timestamp;
	struct filters *next;
};

struct list{
	struct filters *head;
	struct filters *tail;
};

/*
int isEdonkey(int, char);
unsigned int getSize(char *);
*/
struct mapid_edonkey {
	int *shift[1];
	int *skip[1];
	struct list **edonkeylist;
};
/*
struct edonkey_header
{
	char protocol;
	char size[4];
	char type;
};
*/
char edonkey_string[] = "\x03\x02\x00\x70\x72\x01\x00\x00\x00";
int isEdonkeyString(mapidflib_function_instance_t *instance, unsigned char *pkt, unsigned int len);

static int edonkey_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{
	int i = 0;

	instance->internal_data = malloc(sizeof(struct mapid_edonkey));
	((struct mapid_edonkey*)instance->internal_data)->edonkeylist = (struct list**)malloc(sizeof(struct list*)*HASHTABLESIZE);
	memset(((struct mapid_edonkey*)instance->internal_data)->edonkeylist, 0, (sizeof(struct list*)*HASHTABLESIZE));
	for(i = 0; i < HASHTABLESIZE; i++) {
		((struct mapid_edonkey*)instance->internal_data)->edonkeylist[i] = (struct list*)malloc(sizeof(struct list));
		((struct mapid_edonkey*)instance->internal_data)->edonkeylist[i]->head = NULL;
		((struct mapid_edonkey*)instance->internal_data)->edonkeylist[i]->tail = NULL;
	}

	((struct mapid_edonkey*)instance->internal_data)->shift[0] = make_shift(edonkey_string, 9);
	((struct mapid_edonkey*)instance->internal_data)->skip[0] = make_skip(edonkey_string, 9);

	return 0;
}	


int isEdonkeyString(mapidflib_function_instance_t *instance, unsigned char *pkt, unsigned int len) {
	
	if(len < 9)
		return -1;
	
	if(len >= 100) {
		if(mSearch((char *)(pkt), 100, edonkey_string, 9,
					((struct mapid_edonkey *)instance->internal_data)->skip[0],
					((struct mapid_edonkey *)instance->internal_data)->shift[0]))
		{
			return 0;
		}
	}
	else {
		if(mSearch((char *)(pkt), len, edonkey_string, 9,
					((struct mapid_edonkey *)instance->internal_data)->skip[0],
					((struct mapid_edonkey *)instance->internal_data)->shift[0]))
		{
			return 0;
		}
	}

	return -1;

}

int isEdonkey(int proto, char c)
{
	if(proto == 6)
	{
		switch(c)
		{
			/* Client <-> Server */
			case((char)EDONKEY_PROTO_EDONKEY):
			case((char)EDONKEY_PROTO_EMULE_EXT):
			case((char)EDONKEY_PROTO_EMULE_COMP):
			case((char)EDONKEY_MSG_HELLO):
			case((char)EDONKEY_MSG_BAD_PROTO):
			case((char)EDONKEY_MSG_GET_SERVER_LIST):
			case((char)EDONKEY_MSG_OFFER_FILES):
			case((char)EDONKEY_MSG_SEARCH_FILES):
			case((char)EDONKEY_MSG_DISCONNECT):
			case((char)EDONKEY_MSG_GET_SOURCES):
			case((char)EDONKEY_MSG_SEARCH_USER):
			case((char)EDONKEY_MSG_CLIENT_CB_REQ):
			case((char)EDONKEY_MSG_MORE_RESULTS):
			case((char)EDONKEY_MSG_SERVER_LIST):
			case((char)EDONKEY_MSG_SEARCH_FILE_RESULTS):
			case((char)EDONKEY_MSG_SERVER_STATUS):
			case((char)EDONKEY_MSG_SERVER_CB_REQ):
			case((char)EDONKEY_MSG_CALLBACK_FAIL):
			case((char)EDONKEY_MSG_SERVER_MESSAGE):
			case((char)EDONKEY_MSG_ID_CHANGE):
			case((char)EDONKEY_MSG_SERVER_INFO_DATA):
			case((char)EDONKEY_MSG_FOUND_SOURCES):
			case((char)EDONKEY_MSG_SEARCH_USER_RESULTS):
				return 1;
			
			/* Client <-> Client */
			case((char)EDONKEY_MSG_HELLO_CLIENT):
			case((char)EDONKEY_MSG_SENDING_PART):
			case((char)EDONKEY_MSG_REQUEST_PARTS):
			case((char)EDONKEY_MSG_NO_SUCH_FILE):
			case((char)EDONKEY_MSG_END_OF_DOWNLOAD):
			case((char)EDONKEY_MSG_VIEW_FILES):
			case((char)EDONKEY_MSG_VIEW_FILES_ANSWER):
			case((char)EDONKEY_MSG_HELLO_ANSWER):
			case((char)EDONKEY_MSG_NEW_CLIENT_ID):
			case((char)EDONKEY_MSG_CLIENT_MESSAGE):
			case((char)EDONKEY_MSG_FILE_STATUS_REQUEST):
			case((char)EDONKEY_MSG_FILE_STATUS):
			case((char)EDONKEY_MSG_HASHSET_REQUEST):
			case((char)EDONKEY_MSG_HASHSET_ANSWER):
			case((char)EDONKEY_MSG_SLOT_REQUEST):
			case((char)EDONKEY_MSG_SLOT_GIVEN):
			case((char)EDONKEY_MSG_SLOT_RELEASE):
			case((char)EDONKEY_MSG_SLOT_TAKEN):
			case((char)EDONKEY_MSG_FILE_REQUEST):
			case((char)EDONKEY_MSG_FILE_REQUEST_ANSWER):
			case((char)EDONKEY_MSG_GET_SHARED_DIRS):
			case((char)EDONKEY_MSG_GET_SHARED_FILES):
			case((char)EDONKEY_MSG_SHARED_DIRS):
			case((char)EDONKEY_MSG_SHARED_FILES):
			case((char)EDONKEY_MSG_SHARED_DENIED):
				return 2;
			
			/* EMULE EXTENSIONS */
			case((char)EMULE_MSG_HELLO_ANSWER):
			case((char)EMULE_MSG_SOURCES_REQUEST):
			case((char)EMULE_MSG_SOURCES_ANSWER):
				return 3;
		}
	}
	else if(proto == 17)	// UDP
	{
		switch(c)
		{
			/* EDONKEY UDP MESSAGES */
			case((char)EDONKEY_MSG_UDP_SERVER_STATUS_REQUEST):
			case((char)EDONKEY_MSG_UDP_SERVER_STATUS):
			case((char)EDONKEY_MSG_UDP_SEARCH_FILE):
			case((char)EDONKEY_MSG_UDP_SEARCH_FILE_RESULTS):
			case((char)EDONKEY_MSG_UDP_GET_SOURCES):
			case((char)EDONKEY_MSG_UDP_FOUND_SOURCES):
			case((char)EDONKEY_MSG_UDP_CALLBACK_REQUEST):
			case((char)EDONKEY_MSG_UDP_CALLBACK_FAIL):
			case((char)EDONKEY_MSG_UDP_SERVER_LIST):
			case((char)EDONKEY_MSG_UDP_GET_SERVER_INFO):
			case((char)EDONKEY_MSG_UDP_SERVER_INFO):
			case((char)EDONKEY_MSG_UDP_GET_SERVER_LIST):
				return 4;
	
			/* EMULE UDP EXTENSIONS */
			case((char)EMULE_MSG_UDP_REASKFILEPING):
			case((char)EMULE_MSG_UDP_REASKACK):
			case((char)EMULE_MSG_UDP_FILE_NOT_FOUND):
				case((char)EMULE_MSG_UDP_QUEUE_FULL):
				return 5;
			
			/* OVERNET UDP EXTENSIONS */
				case((char)OVERNET_MSG_UDP_CONNECT):
			case((char)OVERNET_MSG_UDP_CONNECT_REPLY):
			case((char)OVERNET_MSG_UDP_PUBLICIZE):
			case((char)OVERNET_MSG_UDP_PUBLICIZE_ACK):
			case((char)OVERNET_MSG_UDP_SEARCH):
			case((char)OVERNET_MSG_UDP_SEARCH_NEXT):
				case((char)OVERNET_MSG_UDP_SEARCH_INFO):
			case((char)OVERNET_MSG_UDP_SEARCH_RESULT):
			case((char)OVERNET_MSG_UDP_SEARCH_END):
			case((char)OVERNET_MSG_UDP_PUBLISH):
				case((char)OVERNET_MSG_UDP_PUBLISH_ACK):
				case((char)OVERNET_MSG_UDP_IDENTIFY_REPLY):
				case((char)OVERNET_MSG_UDP_IDENTIFY_ACK):
				case((char)OVERNET_MSG_UDP_FIREWALL_CONNECTION):
					case((char)OVERNET_MSG_UDP_FIREWALL_CONNECTION_ACK):
				case((char)OVERNET_MSG_UDP_FIREWALL_CONNECTION_NACK):
			case((char)OVERNET_MSG_UDP_IP_QUERY):
				case((char)OVERNET_MSG_UDP_IP_QUERY_ANSWER):
			case((char)OVERNET_MSG_UDP_IP_QUERY_END):
			case((char)OVERNET_MSG_UDP_IDENTIFY):
				return 6;
			
		}
	}
	
	switch(c)
	{
		/* EDONKEY SEARCH TYPES */
		case((char)EDONKEY_SEARCH_BOOL):
		case((char)EDONKEY_SEARCH_NAME):
		case((char)EDONKEY_SEARCH_META):
		case((char)EDONKEY_SEARCH_LIMIT):
			return 7;
	}

	return 0;
}

unsigned int getSize(char *p)
{
	unsigned int size = 0;
	int i = 0;
	int base = 1;
	
	for(i = 0; i < 4; i++)
	{
		size += p[i]&0x0f * base;
		base = base * 16;

		size += (p[i]>>4) * base;

		base = base * 16;
	}

	return size;
}

static int edonkey_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			unsigned char* pkt,
			mapid_pkthdr_t* pkt_head)
{
	struct filters *temp = NULL, *prev = NULL, *new = NULL;
	unsigned char *p = NULL;
	
	struct list **edonkeylist = ((struct mapid_edonkey*)instance->internal_data)->edonkeylist;
	uint16_t ethertype;
	struct ether_header *ep = NULL;
	struct pos_header {
		uint16_t af;
		uint16_t cf;
	}	*pp = NULL;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	int ether_len =0 , ip_len = 0, tcp_len = 0, udp_len = 0;
	struct timeval ts;
	unsigned int len = pkt_head->caplen;

	struct vlan_802q_header *vlan_header;

	struct edonkey_header *edonkey_h;

	unsigned int saddr, daddr;
	struct in_addr source, dest;

	uint16_t sp, dp;

	unsigned int hashval = 0;
	
	int pkt_color = pkt_head->color;

	if(pkt_color != 0 && pkt_color != EDONKEY_COLOR) {
		return 0;
	}

	p = pkt;

	switch(instance->hwinfo->link_type) {
		case DLT_EN10MB:
				// lay the Ethernet header struct over the packet data
				ep = (struct ether_header *)p;
				ether_len = sizeof(struct ether_header);

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
				ether_len = sizeof(struct pos_header);

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
		len -= tcph->doff * 4;

		if((unsigned int)(p - pkt) == pkt_head->caplen) {
			return 0;
		}

	}
	else if(iph->protocol == 17)	// UDP
	{
		udph = (struct udphdr *)p;
		udp_len = sizeof(struct udphdr);

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

	for(temp = edonkeylist[hashval]->head, prev = edonkeylist[hashval]->head; temp != NULL; prev = temp, temp = temp->next)
	{
			if(temp->protocol == iph->protocol &&
					(
					(temp->saddr == saddr && temp->daddr == daddr && temp->sp == sp && temp->dp == dp)
					||
					(temp->saddr == daddr && temp->daddr == saddr && temp->sp == dp && temp->dp == sp))
			  )
			{
				gettimeofday(&(temp->last_timestamp), NULL);
				
				if(iph->protocol == 6 && tcph->fin) {
					if(temp == edonkeylist[hashval]->head) {
						edonkeylist[hashval]->head = temp->next;
					}
					else {
						prev->next = temp->next;
					}
					temp->next = NULL;
					free(temp);
				}
				
				pkt_head->color = EDONKEY_COLOR;

				return 1;
			}
			else if(ts.tv_sec - temp->last_timestamp.tv_sec > 60) {
				if(temp == edonkeylist[hashval]->head) {
					edonkeylist[hashval]->head = temp->next;
				}
				else {
					prev->next = temp->next;
				}
				temp->next = NULL;
				free(temp);
			}
	}

	if(isEdonkeyString(instance, p, len) >= 0) { 
		new = (struct filters*)malloc(sizeof(struct filters));
		
		new->protocol = iph->protocol;
		new->saddr = saddr;
		new->daddr = daddr;
		new->sp = sp;
		new->dp = dp;
		gettimeofday(&(new->last_timestamp), NULL);
	
#ifdef __TRACKFLIB_LOGGING__
		write_to_log("eDonkey", "03020070720100000", iph->protocol, source, sp, dest, dp, p, len);
#endif
		for(temp = edonkeylist[hashval]->head; temp != NULL; temp = temp->next) {
			if(new->protocol == temp->protocol && (
						(new->saddr == temp->saddr && new->daddr == temp->daddr && new->sp == temp->sp && new->dp == temp->dp) 
						||
						(new->daddr == temp->saddr && new->saddr == temp->daddr && new->dp == temp->sp && new->sp == temp->dp)
						)
					)
			{
				pkt_head->color = EDONKEY_COLOR;
				return 1;
			}
		}
		
		new->next = edonkeylist[hashval]->head;
		edonkeylist[hashval]->head = new;
	
		pkt_head->color = EDONKEY_COLOR;
		return 1;
	}
	if(iph->protocol == 6)
	{
		edonkey_h = (struct edonkey_header *)p;
		
		if(edonkey_h->protocol != (char)0xE3 && edonkey_h->protocol != (char)0xC5 && edonkey_h->protocol != (char)0xd4)
		{
			return 0;
		}
		
		if(getSize(edonkey_h->size) != (pkt_head->wlen - ether_len - ip_len - tcp_len - 5))
			return 0;

		
		if(isEdonkey(iph->protocol, edonkey_h->type) == 0)
			return 0;
	}
	else if(iph->protocol == 17)
	{
		edonkey_h = (struct edonkey_header *)p;
	
		if(edonkey_h->protocol != (char)0xe3 && edonkey_h->protocol != (char)0xC5 && edonkey_h->protocol != (char)0xd4)
		{

			return 0;
		}
		
		if(getSize(edonkey_h->size) != (pkt_head->caplen - ether_len - ip_len - udp_len - 5))
		{
			if(isEdonkey(iph->protocol, edonkey_h->size[0]) == 0)
				return 0;
		}

		
		if(isEdonkey(iph->protocol, edonkey_h->type) == 0)
			return 0;
	}
	else
	{
		return 0;
	}
		
	new = (struct filters*)malloc(sizeof(struct filters));
	
	new->protocol = iph->protocol;
	new->saddr = saddr;
	new->daddr = daddr;
	new->sp = sp;
	new->dp = dp;
	gettimeofday(&(new->last_timestamp), NULL);
#ifdef __TRACKFLIB_LOGGING__	
	write_to_log("eDonkey", "No String match", iph->protocol, source, sp, dest, dp, p, len);
#endif
	for(temp = edonkeylist[hashval]->head; temp != NULL; temp = temp->next)
	{
		if(new->protocol == temp->protocol && (
				(new->saddr == temp->saddr && new->daddr == temp->daddr && new->sp == temp->sp && new->dp == temp->dp) 
				||
				(new->daddr == temp->saddr && new->saddr == temp->daddr && new->dp == temp->sp && new->sp == temp->dp)
				)
			)
		{
			pkt_head->color = EDONKEY_COLOR;
			free(new);
			return 1;
		}
	}

	new->next = edonkeylist[hashval]->head;
	edonkeylist[hashval]->head = new;
	pkt_head->color = EDONKEY_COLOR;
			
	return 1;
}

static int edonkey_cleanup(mapidflib_function_instance_t *instance) 
{
	struct filters *temp = NULL, *tmp = NULL;
	int i = 0;
	
  if(instance->internal_data != NULL){

	  for(i = 0; i < HASHTABLESIZE; i++) {
		  temp = ((struct mapid_edonkey*)instance->internal_data)->edonkeylist[i]->head;
		  
		  while(temp != NULL) {
			  tmp = temp;
			  temp = temp->next;
			  free(tmp);
		  }
		  free(((struct mapid_edonkey*)instance->internal_data)->edonkeylist[i]);
	  }

	  free(((struct mapid_edonkey*)instance->internal_data)->shift[0]);
	  free(((struct mapid_edonkey*)instance->internal_data)->skip[0]);
	  
	  free(((struct mapid_edonkey*)instance->internal_data)->edonkeylist);
	  free(instance->internal_data);
  }
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "TRACK_EDONKEY",
  "Searches for eDonkey packets\n",
  "",
  MAPI_DEVICE_ALL,
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_NONE,
  NULL,
  edonkey_init,
  edonkey_process,
  NULL, //get_result
  NULL, //reset
  edonkey_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* edonkey_get_funct_info();
mapidflib_function_def_t* edonkey_get_funct_info() {
  return &finfo;
};

