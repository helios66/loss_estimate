#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pcap.h>		/* DLT_EN10MB */
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "topx.h"
#include "protocols.h"
#include "mapi_errors.h"

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif

struct topx_field {
	void *pointer;
	char needs_reverse;
	unsigned int len;
	unsigned short value; /* used when cannot pass pointer directly into packet data */
};

void extract_field(struct topx_field *field, unsigned char *ip_pkt, size_t length, int protocol, int pfield);
struct topx_hash_node *hash_lookup(struct topx_val *value, struct topx_data *data); 
void check_for_shift(struct topx_data *data,struct topx_list_node *node); 
void add_to_hashtable_and_list(struct topx_data *data, struct topx_val *value, unsigned long long bytes, unsigned int last_rst); 
void add_field_to_list(struct topx_field *field,struct topx_data *data,unsigned long long bytes,unsigned int last_rst); 

/* returns NULL on error */
static unsigned char *find_hdrs(unsigned char *type, unsigned char *fragoff0, unsigned char wanted, unsigned char *ip6_pkt, size_t length) {
	unsigned char *p;
	struct ip6_frag *frag;
	
	if (sizeof(struct ip6_hdr) > length)
		return NULL;

	*fragoff0 = 1;
	*type = ((struct ip6_hdr *)ip6_pkt)->ip6_nxt;
	p = ip6_pkt + sizeof(struct ip6_hdr);

	for (;;) {
		if (*type == wanted)
			return p;
		switch (*type) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
			if (p + 8 > ip6_pkt + length) /* option is at least 8 long */
				return NULL;
			*type = *p++;
			p += 7 + 8 * *p; /* 7 bytes + 8 * len bytes */
			break;
		case IPPROTO_FRAGMENT:
			frag = (struct ip6_frag *)p;
			if (p + 8 > ip6_pkt + length) /* option is 8 bytes long */
				return NULL;
			*fragoff0 = (frag->ip6f_offlg & IP6F_OFF_MASK) ? 0 : 1;
			*type = frag->ip6f_nxt;
			p += 8;
			break;
		default:
			return p;
		}
	}
}

void extract_field(struct topx_field *field, unsigned char *ip_pkt, size_t length, int protocol, int pfield) {
	
	ip_header* ip;
	struct ip6_hdr *ip6;
	uint8_t ip_ver;
	int ip_len;
	unsigned char next, fragoff0;
	struct ip6_frag *frag6;
	tcp_header* tcp;
	udp_header* udp;

	field->len = 0;

	if (length < sizeof(ip_header))
		return;

	ip = (ip_header *)ip_pkt;
	ip_ver = ip->ver_ihl >> 4;
	if (ip_ver == 4)
		ip_len = (ip->ver_ihl & 0xf) * 4;
	else if (ip_ver == 6) {
		ip6 = (struct ip6_hdr *)ip_pkt;
		if (length < sizeof(struct ip6_hdr))
			return;
	} else
		return; /* Only support versions 4 and 6 */

	field->needs_reverse=0;
	
	switch(protocol) {
		case TOPX_IP:
			switch(pfield) {
				case TOPX_IP_TOS:
					if (ip_ver == 4) {
						field->pointer = &ip->tos;
						field->len = 1;
					} else { /* For IPv6, extract bit 5-12 */
						unsigned char *flowbytes = (unsigned char *)&ip6->ip6_flow;
						field->value = (flowbytes[0] & 0xf) * 16 + (flowbytes[1] >> 4);
						field->pointer = &field->value;
						field->len = 2;
					}
					break;
				case TOPX_IP_LENGTH:
					if (ip_ver == 4) {
						field->pointer = &ip->tlen;
						field->needs_reverse = 1;
					} else { /* For IPv6, total length = 40 + payload length */
						field->value = 40 + ntohs(ip6->ip6_plen);
						field->pointer = &field->value;
					}
					field->len=2;
					break;
				case TOPX_IP_ID:
					if (ip_ver == 4) {
						field->pointer = &ip->id;
						field->needs_reverse = 1;
						field->len = 2;
					} else {
						frag6 = (struct ip6_frag *)find_hdrs(&next, &fragoff0, IPPROTO_FRAGMENT, ip_pkt, length);
						if (frag6 && next == IPPROTO_FRAGMENT && (unsigned char *)frag6 + sizeof(struct ip6_frag) <= ip_pkt + length) {
							field->pointer = &frag6->ip6f_ident;
							field->needs_reverse = 1;
						} else {
							field->value = 0;
							field->pointer = &field->value;
						}
						field->len = 4;
					}
					break;
				case TOPX_IP_OFFSET:
					if (ip_ver == 4) {
						field->pointer = &ip->off;
						field->needs_reverse = 1;
					} else {
						frag6 = (struct ip6_frag *)find_hdrs(&next, &fragoff0, IPPROTO_FRAGMENT, ip_pkt, length);
						if (frag6 && next == IPPROTO_FRAGMENT && (unsigned char *)frag6 + sizeof(struct ip6_frag) <= ip_pkt + length) {
							field->pointer = &frag6->ip6f_offlg;
							field->needs_reverse = 1;
						} else {
							field->value = 0;
							field->pointer = &field->value;
						}
					}
					field->len = 2;
					break;
				case TOPX_IP_TTL:
					field->pointer = (ip_ver == 4) ? &ip->ttl : &ip6->ip6_hlim;
					field->len=1;
					break;
				case TOPX_IP_PROTOCOL:
					field->pointer=&(ip->ptcl);
					field->len=1;
					break;
				case TOPX_IP_CHECKSUM:
					if (ip_ver == 4)
						field->pointer = &ip->sum;
					else { /* No checksum in IPv6 header */
						field->value = 0;
						field->pointer = &field->value;
					}
					field->len=2;
					break;
				case TOPX_IP_SRCIP:
					if (ip_ver == 4) {
						field->pointer = &ip->saddr;
						field->len = 4;
					} else {
						field->pointer = &ip6->ip6_src;
						field->len = 16;
					}
					break;
				case TOPX_IP_DSTIP:
					if (ip_ver == 4) {
						field->pointer = &ip->daddr;
						field->len = 4;
					} else {
						field->pointer = &ip6->ip6_dst;
						field->len = 16;
					}
					break;
			}
			break;
		case TOPX_TCP:
			if (ip_ver == 4) {
				if (ip->ptcl != IPPROTO_TCP || ntohs(ip->off) & 0x1fff) /* no TCP packet or no TCP header */
					return;
				tcp = (tcp_header *)(ip_pkt + ip_len);
			} else { /* IPv6 */
				tcp = (tcp_header *)find_hdrs(&next, &fragoff0, IPPROTO_TCP, ip_pkt, length);
				if (!tcp || next != IPPROTO_TCP || !fragoff0)
					return;
			}
			if ((unsigned char *)tcp + sizeof(tcp_header) > ip_pkt + length)
				return; /* Not room for tcp header in packet */
			
			//tcp_len = tcp->off * 4;
			switch(pfield) {
				case TOPX_TCP_SRCPORT:
					field->needs_reverse=1;
					field->pointer=&(tcp->sport);
					field->len=2;
					break;
				case TOPX_TCP_DSTPORT:
					field->needs_reverse=1;
					field->pointer=&(tcp->dport);
					field->len=2;
					break;
				case TOPX_TCP_SEQ:
					field->pointer=&(tcp->seq);
					field->len=4;
					break;
				case TOPX_TCP_ACK:
					field->pointer=&(tcp->ack);
					field->len=4;
					break;
				case TOPX_TCP_FLAGS:
					field->pointer=&(tcp->flags);
					field->len=2;
					break;
				case TOPX_TCP_WIN:
					field->pointer=&(tcp->win);
					field->len=2;
					break;
				case TOPX_TCP_CRC:
					field->pointer=&(tcp->crc);
					field->len=2;
					break;
				case TOPX_TCP_URGENT:
					field->pointer=&(tcp->urp);
					field->len=2;
					break;
			}
			break;
		case TOPX_UDP:
			if (ip_ver == 4) {
				if (ip->ptcl != IPPROTO_UDP || ntohs(ip->off) & 0x1fff) /* no UDP packet or no UDP header */
					return;
				udp = (udp_header *)(ip_pkt + ip_len);
			} else { /* IPv6 */
				udp = (udp_header *)find_hdrs(&next, &fragoff0, IPPROTO_UDP, ip_pkt, length);
				if (!udp || next != IPPROTO_UDP || !fragoff0)
					return;
			}
			if ((unsigned char *)udp + sizeof(udp_header) > ip_pkt + length)
				return; /* Not room for udp header in packet */
			
			switch(pfield) {
				case TOPX_UDP_SRCPORT:
					field->needs_reverse=1;
					field->pointer=&(udp->sport);
					field->len=2;
					break;
				case TOPX_UDP_DSTPORT:
					field->needs_reverse=1;
					field->pointer=&(udp->dport);
					field->len=2;
					break;
				case TOPX_UDP_LENGTH:
					field->pointer=&(udp->length);
					field->len=2;
					break;
				case TOPX_UDP_CHECKSUM:
					field->pointer=&(udp->sum);
					field->len=2;
					break;	
			}
		default:
			break;
	}
}

struct topx_hash_node *hash_lookup(struct topx_val *value, struct topx_data *data) {
	unsigned int pos;
	struct topx_hash_node *tmp;

	if (value->len == 1) {
		pos = value->val[0] % TOPX_HASH_SIZE;
		for (tmp = data->hashtable[pos]; tmp; tmp=tmp->next)
			if (tmp->value.len == 1 && tmp->value.val[0] == value->val[0])
				return tmp;
	} else { /* length 1 or 4, so assuming 4 */
		pos = (value->val[0] ^ value->val[1] ^ value->val[2] ^ value->val[3]) % TOPX_HASH_SIZE;
		for (tmp = data->hashtable[pos]; tmp; tmp=tmp->next)
			if (tmp->value.len == 4 && !memcmp(tmp->value.val, value->val, 16 /* 4 * sizeof(unsigned int) */))
				return tmp;
	}

	return NULL;
}

void check_for_shift(struct topx_data *data,struct topx_list_node *node) {
	struct topx_list_node *before;

	before = node;
	if (data->sortby == SORT_BY_PACKETS)
		for (; before->previous && before->previous->count < node->count; before = before->previous);
	else
		for (; before->previous && before->previous->bytecount < node->bytecount; before = before->previous);

	if (before == node)
		return;
	
	/* delete node from its current place */
	node->previous->next = node->next;
	if (node->next) 
		node->next->previous = node->previous;
	else
		data->list_tail = node->previous;

	/* insert in front of before */
	node->next = before;
	if (before->previous)
		before->previous->next = node;
	else 
		data->list_head = node;
	
	node->previous = before->previous;
	before->previous = node;
}

void add_to_hashtable_and_list(struct topx_data *data, struct topx_val *value, unsigned long long bytes, unsigned int last_rst) {
	unsigned int pos;
	struct topx_list_node *newlistnode;
	struct topx_hash_node *newhashnode;
	
	newlistnode=(struct topx_list_node *)malloc(sizeof(struct topx_list_node));
	bzero(newlistnode, sizeof(struct topx_list_node));
	newlistnode->value = *value;
	newlistnode->count=1;
	newlistnode->bytecount=bytes;
	newlistnode->last_rst_secs=last_rst;
	newlistnode->next=newlistnode->previous=NULL;

	//add to list
	data->list_size++;

	if(data->list_tail==NULL) {
		data->list_head=data->list_tail=newlistnode;
	}
	else {
		data->list_tail->next=newlistnode;
		newlistnode->previous=data->list_tail;
		data->list_tail=newlistnode;
	}

	pos = ((value->len == 1)
	       ? value->val[0]
	       : value->val[0] ^ value->val[1] ^ value->val[2] ^ value->val[3])
		% TOPX_HASH_SIZE;
	newhashnode=(struct topx_hash_node *)malloc(sizeof(struct topx_hash_node));
	bzero(newhashnode, sizeof(struct topx_hash_node));
	newhashnode->value = *value;
	newhashnode->node=newlistnode;
	newhashnode->next=data->hashtable[pos];
	data->hashtable[pos]=newhashnode;
	
}

void add_field_to_list(struct topx_field *field,struct topx_data *data,unsigned long long bytes, unsigned int last_rst) {
	struct topx_hash_node *lookup;
	struct topx_val value;
	
	bzero(&value, sizeof(struct topx_val));
	
	switch(field->len) {
		case 1:
			value.len = 1;
			value.val[0] = (unsigned int)(*((unsigned char *)(field->pointer)));
			break;
		case 2:
			value.len = 1;
			if(field->needs_reverse==1)
				value.val[0] = (unsigned int)(ntohs(*((unsigned short *)(field->pointer))));	
			else 
				value.val[0] = (unsigned int)(*((unsigned short *)(field->pointer)));	
			break;
		case 4:
			value.len = 1;
			if(field->needs_reverse==1)
				value.val[0] = ntohl((*((unsigned int *)(field->pointer))));	
			else
				value.val[0] = (*((unsigned int *)(field->pointer)));	
			break;
	        case 16:
			value.len = 4;
			memcpy(value.val, field->pointer, 16);
		default:
			break;
	}
	
	lookup = hash_lookup(&value, data);
	if(lookup==NULL) {
		add_to_hashtable_and_list(data, &value, bytes, last_rst);	
	}
	else {
		lookup->node->count++;
		lookup->node->bytecount+=bytes;
		lookup->node->last_rst_secs=last_rst;

		check_for_shift(data,lookup->node);
	}
}
static int topx_reset(mapidflib_function_instance_t *instance){

	struct topx_list_node *tmp,*next;
	struct topx_data *data;
	struct topx_hash_node **htable;
	struct topx_hash_node *htmp,*hnext;
	int i=0;

	data=(struct topx_data *)(instance->internal_data);
	
	tmp=data->list_head;

	while(tmp) {
		next=tmp->next;
		free(tmp);
		tmp=next;
	}

	data->list_head = data->list_tail=NULL;
	data->list_size=0;

	htable=data->hashtable;

	for(i=0;i<TOPX_HASH_SIZE;i++) {
		htmp=htable[i];
		while(htmp) {
			hnext=htmp->next;
			free(htmp);
			htmp=hnext;
		}
	}

	memset(htable,0,TOPX_HASH_SIZE*sizeof(struct topx_hash_node *));
    
	return 0;
}

static int topx_cleanup(mapidflib_function_instance_t *instance){

	struct topx_list_node *tmp,*next;
	struct topx_data *data;
	struct topx_hash_node **htable;
	struct topx_hash_node *htmp,*hnext;
	int i=0;

	data=(struct topx_data *)(instance->internal_data);
	
	tmp=data->list_head;

	while(tmp) {
		next=tmp->next;
		free(tmp);
		tmp=next;
	}

	data->list_head = data->list_tail=NULL;
	data->list_size=0;

	htable=data->hashtable;

	for(i=0;i<TOPX_HASH_SIZE;i++) {
		htmp=htable[i];
		while(htmp) {
			hnext=htmp->next;
			free(htmp);
			htmp=hnext;
		}
	}

	free(data);
	memset(htable,0,TOPX_HASH_SIZE*sizeof(struct topx_hash_node *));
    
	return 0;
}

int pktcnt=0;

#define ETHERTYPE_8021Q 0x8100
#define MPLS_MASK 0x8847

struct vlan_802q_header {
	u_int16_t priority_cfi_vid;
	u_int16_t ether_type;
};


static int topx_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			MAPI_UNUSED mapid_pkthdr_t* pkt_head)  
{
	
	unsigned char *packet=(unsigned char *)link_pkt;
	struct topx_field field;
	struct topx_data *data=(struct topx_data *)(instance->internal_data);
	struct topx_list_node *tmp;
	int i=0;
	unsigned int *ptr;
	struct topx_result *result;
//	struct timeval ts;
	unsigned int cur_secs = 0;
	struct timeval tv;
	int linkhdr_len;
	uint16_t ethertype;
	struct ether_header *ep = NULL;
	struct vlan_802q_header *vlan_header = NULL;

	switch (instance->hwinfo->link_type) {
	case DLT_EN10MB: /* ethernet */
					linkhdr_len = sizeof(ether_header);
					ep = (struct ether_header*)dev_pkt;
					ethertype = ntohs(ep->ether_type);

					if(ethertype == ETHERTYPE_8021Q) {
							linkhdr_len += sizeof(struct vlan_802q_header);
							vlan_header = (struct vlan_802q_header*)(dev_pkt + linkhdr_len);
							ethertype = ntohs(vlan_header->ether_type);
					}
					if(ethertype == MPLS_MASK) {
							linkhdr_len += 4;
					}
					extract_field(&field, packet + linkhdr_len,
							pkt_head->wlen - linkhdr_len, data->protocol, data->field);
					break;
	case DLT_CHDLC:
		linkhdr_len = 20;
		if (ntohs(*(uint16_t*)(dev_pkt + 18)) == ETHERTYPE_IP) {
			extract_field(&field, dev_pkt + linkhdr_len,
				pkt_head->wlen - linkhdr_len, data->protocol, data->field);
		}
		break;
	default:
		assert(0);
	}

	if(field.len==0) 
		return 1;

	//gettimeofday(&ts, NULL);

/*	if(data->reset_interval > 0) { // IF < 0 then no reseting
		if(data->previous_reset.tv_sec == 0)
			data->previous_reset = ts;
		else if(ts.tv_sec - data->previous_reset.tv_sec > data->reset_interval) {
			printf("reseting top %llu %llu\n", pkt_head->ts, data->previous_reset);
			topx_reset(instance);
			data->previous_reset = ts;
		}
	}
*/
	if(data->reset_interval > 0) { // IF < 0 then no reseting
		cur_secs = pkt_head->ts >> 32;
		if(data->previous_reset == 0) {
			data->previous_reset = cur_secs;
		}
		else if(cur_secs - data->previous_reset > data->reset_interval) {
			topx_reset(instance);
			data->previous_reset = cur_secs;
			gettimeofday(&tv, NULL);
			data->last_rst = tv.tv_sec * 1000000 + tv.tv_usec;
		}
	}
	
	//printf("---- %lf\n",(double)(pkt_head->wlen));
	add_field_to_list(&field,data,(unsigned long long)(pkt_head->wlen - linkhdr_len), data->last_rst);
	
	tmp=data->list_head;

	ptr=(unsigned int *)(instance->result.data);
	//write the number of results
	if(data->list_size<=data->x) 
		*ptr=data->list_size;
	else 
		*ptr=data->x;
	
	ptr++;
	
	//write results
	result=(struct topx_result *)ptr;
	
	while (tmp && i < data->x) {
		if (tmp->value.len == 1)
			result->value = tmp->value.val[0];
		else    /* len != 1 only for IPv6 addresses */
			memcpy(&result->addr6, tmp->value.val, 16);
		
		if (data->field == TOPX_IP_SRCIP || data->field == TOPX_IP_DSTIP)
			result->family = (tmp->value.len == 1) ? AF_INET : AF_INET6;

		result->count=tmp->count;
		result->bytecount=tmp->bytecount;
		result->last_rst_secs=tmp->last_rst_secs;
		result++;

		tmp=tmp->next;
		i++;
	}
    return 1;
}

static int topx_instance(mapidflib_function_instance_t *instance,
			     MAPI_UNUSED int flow_descr,
			     MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
	mapiFunctArg *fargs = instance->args;
	int x;

	if ( (x=getargint(&fargs)) > TOPX_MAX_X)
		return MFUNCT_INVALID_ARGUMENT_1;

	instance->def->shm_size=sizeof(struct topx_result) * x + sizeof(unsigned int);

	int protocol = getargint(&fargs);

	if(protocol!=TOPX_IP &&  protocol!=TOPX_TCP && protocol!=TOPX_UDP)
		return MFUNCT_INVALID_ARGUMENT_2;

	int field = getargint(&fargs);

	if(field < TOPX_IP_TOS || field > TOPX_UDP_CHECKSUM)		// add checking for field argument
		return MFUNCT_INVALID_ARGUMENT_3;
	
	if(protocol == TOPX_IP && (field < TOPX_IP_TOS || field > TOPX_IP_DSTIP))
		return MFUNCT_INVALID_ARGUMENT_3;

	if(protocol == TOPX_TCP && (field < TOPX_TCP_SRCPORT || field > TOPX_TCP_URGENT))
		return MFUNCT_INVALID_ARGUMENT_3;

	if(protocol == TOPX_UDP && (field < TOPX_UDP_SRCPORT || field > TOPX_UDP_CHECKSUM))
		return MFUNCT_INVALID_ARGUMENT_3;

	return(0);
}

static int topx_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{
	mapiFunctArg* fargs;
	int x,protocol,field,sortby,reset_interval;
	struct timeval tv;
	
  	fargs=instance->args;
	x = getargint(&fargs);
	if (x < 1) 
		x=1;

	protocol = getargint(&fargs);
	if(protocol!=TOPX_IP &&  protocol!=TOPX_TCP && protocol!=TOPX_UDP)
		return MFUNCT_INVALID_ARGUMENT_2;
	
	field = getargint(&fargs);

	if(field < TOPX_IP_TOS || field > TOPX_UDP_CHECKSUM)		// add checking for field argument
		return MFUNCT_INVALID_ARGUMENT_3;
	
	if(protocol == TOPX_IP && (field < TOPX_IP_TOS || field > TOPX_IP_DSTIP))
		return MFUNCT_INVALID_ARGUMENT_3;

	if(protocol == TOPX_TCP && (field < TOPX_TCP_SRCPORT || field > TOPX_TCP_URGENT))
		return MFUNCT_INVALID_ARGUMENT_3;

	if(protocol == TOPX_UDP && (field < TOPX_UDP_SRCPORT || field > TOPX_UDP_CHECKSUM))
		return MFUNCT_INVALID_ARGUMENT_3;

	sortby = getargint(&fargs);
	reset_interval = getargint(&fargs);

	if(sortby!= SORT_BY_BYTES && sortby!= SORT_BY_PACKETS)
		sortby = SORT_BY_PACKETS;
	
	instance->internal_data = malloc(sizeof(struct topx_data));
	((struct topx_data *)(instance->internal_data))->x=x;
	((struct topx_data *)(instance->internal_data))->protocol=protocol;
	((struct topx_data *)(instance->internal_data))->field=field;
	((struct topx_data *)(instance->internal_data))->sortby=sortby;
	((struct topx_data *)(instance->internal_data))->reset_interval = reset_interval;
	((struct topx_data *)(instance->internal_data))->previous_reset = 0;
	((struct topx_data *)(instance->internal_data))->list_head=NULL;
	((struct topx_data *)(instance->internal_data))->list_tail=NULL;
	((struct topx_data *)(instance->internal_data))->list_size=0;
	memset(((struct topx_data *)(instance->internal_data))->hashtable,0,TOPX_HASH_SIZE*sizeof(struct topx_hash_node *));
	gettimeofday(&tv, NULL);
	((struct topx_data *)(instance->internal_data))->last_rst = tv.tv_sec * 1000000 + tv.tv_usec;
	return 0;
}

static mapidflib_function_def_t topfinfo={
    "", //libname
    "TOP", //name
    "Returns the TOP x values of a field (e.g DST_PORT)\n\tReturn value: x values of variable type according to field applied", //descr
    "iiiii", //argdescr
    MAPI_DEVICE_ALL, //devoid
    MAPIRES_SHM, //Use shared memory to return results
    0, //shm size. Set by instance
    0, //modifies_pkts
    0, //filters packets
    MAPIOPT_AUTO, //Optimization
    topx_instance,  //instance
    topx_init, //init
    topx_process,
    NULL, //get_result,
    topx_reset, // reset
    topx_cleanup, //cleanup
    NULL, //client_init
    NULL, //client_read_result
    NULL  //client_cleanup
};

mapidflib_function_def_t* topx_get_funct_info();

mapidflib_function_def_t* topx_get_funct_info() {
    return &topfinfo;
};
