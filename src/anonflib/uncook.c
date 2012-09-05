#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "debug.h"
#include "mapiipc.h"

#include "anonymization.h"
#include "../extraflib/cooking.h"


void rebuild_fragments(mapidflib_function_instance_t *instance,flist_t *list,unsigned char *payload,int large_payload_size, mapid_pkthdr_t *mapihdr, int fd);
int myflist_insert_before(flist_t *list, flist_node_t *before, void *data);
flist_t *merge_lists(flist_t *cl,flist_t *sv);

void rebuild_fragments(mapidflib_function_instance_t *instance,flist_t *list,unsigned char *payload,int large_payload_size, mapid_pkthdr_t *mapihdr, int fd) {
	flist_node_t *n = NULL,*prev = NULL;
	struct headers_data *data;
	int p_offset=0;
	mapipacket frag_decoded;
	struct pcap_pkthdr pkthdr;
	int cnt=0;
	mapid_pkthdr_t new_header;

	ether_header* eth = NULL;
	struct ip *iph = NULL;
	struct tcphdr *tcph = NULL;
	int ether_len = 0, ip_len = 0, tcp_len = 0;
	unsigned char* cooked_payload = NULL;
//	unsigned char new_packet[1514];

	flist_t *f = NULL;
	mapidflib_function_t *next_to_me = NULL, *traverse = NULL;
	flist_node_t *node = NULL, *temp_node = NULL;
	
	if(!list) {
		DEBUG_CMD(Debug_Message("No list report in rebuild_fragments"));
		return;
	}
	
	if(!payload) {
		//fprintf(stderr,"No payload report in rebuild_fragments\n");
		return;
	}
	
	DEBUG_CMD(Debug_Message("in rebuild_fragments before getting headers"));
	// get data from large payload

	eth = (ether_header*)payload;
	ether_len = sizeof(ether_header);
	iph = (struct ip*)(payload + ether_len);
	ip_len = (iph->ip_hl & 0xf) * 4;
	if(iph->ip_p != IPPROTO_TCP)	// no TCP packet
		return;

	tcph = (struct tcphdr *)(payload + ether_len + ip_len);
	tcp_len	= tcph->doff * 4;

	cooked_payload = payload + ether_len + ip_len + tcp_len;

	// finished getting data

	DEBUG_CMD(Debug_Message("in rebuild_fragments after getting headers"));
	// get remainder functions from the list
	while(__sync_lock_test_and_set(&(instance->hwinfo->gflist->lock),1));
	
		
	f=flist_get(instance->hwinfo->gflist->fflist,fd);
	node = flist_head(f);
	
	next_to_me = flist_data(node);;	

	while(next_to_me->instance != instance) {
		node = flist_next(node);
		next_to_me = flist_data(node);
	}
	
	instance->hwinfo->gflist->lock = 0;
			
	// got the functions 

//	printf("in rebuild_fragments after getting the function list:: number of bytes in cooked packet %d large %d\n", mapihdr->caplen, large_payload_size);
	
	for(n=flist_head(list); n != NULL; prev=n,n= flist_next(n)) {
		data=(struct headers_data *)(n->data);
		pkthdr.caplen=data->caplen;
		pkthdr.len=data->wlen;
		pkthdr.ts.tv_sec=data->ts.tv_sec;
		pkthdr.ts.tv_usec=data->ts.tv_usec;

		new_header.caplen = data->caplen;
		new_header.wlen = data->wlen;
		new_header.ts = (data->ts.tv_sec << 8) + data->ts.tv_usec;
		new_header.ifindex = mapihdr->ifindex;
/*
		printf("packet data caplen %d wlen %d\n", pkthdr.caplen, pkthdr.len);
*/
		DEBUG_CMD(Debug_Message("instance->hwinfo->cap_length %d", instance->hwinfo->cap_length));
		//decode_packet(instance->hwinfo->link_type,instance->hwinfo->cap_length,&pkthdr,(unsigned char *)(data->header),&frag_decoded);	
		decode_packet(instance->hwinfo->link_type,data->caplen,&pkthdr,(unsigned char *)(data->header),&frag_decoded);	
//		decode_packet(instance->hwinfo->link_type,instance->hwinfo->cap_length,&pkthdr,payload,&frag_decoded);	
/*
		printf("copying %d data as header\n", data->header_len);
		memcpy(new_packet,data->header, data->header_len);
		printf("copying %d data as payload %d tcp_len %d\n", pkthdr.caplen - data->header_len, pkthdr.caplen, tcp_len);
		memcpy(&new_packet[data->header_len], cooked_payload, pkthdr.caplen - data->header_len);

		cooked_payload = cooked_payload + pkthdr.caplen;

		temp_node = flist_next(node);
//		traverse = flist_data(temp_node);

		while(temp_node != NULL) {
			traverse = flist_data(temp_node);

			printf("calling function %s\n", traverse->instance->def->name);
			traverse->instance->def->process(traverse->instance, new_packet, new_packet, &new_header);
			
			temp_node = flist_next(temp_node);
		}
	}

*/		
	
		if(frag_decoded.dsize==0) {
			continue;
		}
		
		if((large_payload_size-p_offset)<=0) 
			break;
		
		if(frag_decoded.dsize>=(large_payload_size-p_offset)) {
			int fit_len=frag_decoded.dsize;
			if(frag_decoded.dsize>(large_payload_size-p_offset)) 
				fit_len=(large_payload_size-p_offset);
			memcpy(frag_decoded.data,payload+p_offset,fit_len);
			p_offset+=frag_decoded.dsize;
		}
		else {
			int new_frag_size;
			new_frag_size=frag_decoded.dsize;

			if(p_offset<large_payload_size) { //copy the rest
				memcpy(frag_decoded.data,payload+p_offset,new_frag_size);
			}

			p_offset+=new_frag_size;
		}
		
		temp_node = flist_next(node);

		while(temp_node != NULL) {
			traverse = flist_data(temp_node);

			DEBUG_CMD(Debug_Message("calling function %s pkthdr.caplen %d", traverse->instance->def->name, pkthdr.caplen));
			traverse->instance->def->process(traverse->instance, frag_decoded.pkt, frag_decoded.pkt, &new_header);
			
			temp_node = flist_next(temp_node);
		}

		cnt++;
	}
	
/*	if((large_payload_size-p_offset)>0) {
			printf("in here not setting it in zero\n");
			fprintf(stderr,"remaining: %d\n",large_payload_size-p_offset);
			return;		
	}
*/
	
	if((large_payload_size-p_offset)>0) {
		data=(struct headers_data *)prev->data;
		data->caplen=data->wlen=data->caplen+large_payload_size-p_offset;
		DEBUG_CMD(Debug_Message("I have %d flow headers and there are %d bytes remaining", cnt, large_payload_size-p_offset));
		DEBUG_CMD(Debug_Message("new data caplen: %d", data->caplen));
		pkthdr.caplen=data->caplen;
		pkthdr.len=data->wlen;

		//frag_decoded points contains the last decoded packet
		memcpy(frag_decoded.data+frag_decoded.dsize,payload+p_offset,large_payload_size-p_offset);
		
		if(frag_decoded.iph) {
			int previous_len=ntohs(frag_decoded.iph->ip_len);
			previous_len+=(large_payload_size-p_offset);
			frag_decoded.iph->ip_len=ntohs(previous_len);
		}

		memcpy(payload, frag_decoded.pkt, large_payload_size-p_offset);
	
		mapihdr->caplen = new_header.caplen = large_payload_size-p_offset;
		mapihdr->wlen = new_header.wlen = large_payload_size-p_offset;
		mapihdr->ts = new_header.ts = (data->ts.tv_sec << 8) + data->ts.tv_usec;
		mapihdr->ifindex = new_header.ifindex = mapihdr->ifindex;

	}
	else {
		DEBUG_CMD(Debug_Message("in here setting it in zero"));
		mapihdr->caplen = 0;
		return;
	}

	
}

int myflist_insert_before(flist_t *list, flist_node_t *before, void *data)
{
  flist_node_t *newnode,*node,*prev=NULL;
  
  if ( (newnode = malloc(sizeof(flist_node_t))) == NULL )
    return -1;
 	
  newnode->data = data;
  newnode->next = NULL;
  
  //Find before node
  node=flist_head(list);

  if ( node == NULL ) {
	flist_head(list) = newnode;
    	flist_tail(list) = newnode;
  } 
  else {
    	while(node!=NULL) {
    		if(node!=before) {
			prev=node;
			node=flist_next(node);
      		} 
	  	else
			break;
   	}
    
    	if(prev==NULL) {
	  	newnode->next=flist_head(list);
	  	flist_head(list)=newnode;
    	} 
	else {
      		prev->next=newnode;
      		newnode->next=node;
      		if(node==NULL)
			flist_tail(list)=newnode;
    	}
  }
  
  ++flist_size(list);
  return 0;
}

flist_t *merge_lists(flist_t *cl,flist_t *sv) {
	flist_node_t *n,*g;
	struct headers_data *sv_data,*cl_data;
	
	if(cl && !sv) return cl;
	if(sv && !cl) return sv;
	if(!sv && !cl) return NULL;
	
	for(n=flist_head(sv);n!=NULL;n=flist_next(n)) {
		sv_data=(struct headers_data *)(n->data);	
		for(g=flist_head(cl);g!=NULL;g=flist_next(g)) {
			cl_data=(struct headers_data *)(g->data);	
			if(cl_data->ts.tv_sec>sv_data->ts.tv_sec || (cl_data->ts.tv_sec==sv_data->ts.tv_sec && cl_data->ts.tv_usec>=sv_data->ts.tv_usec))
				break;
		}
		
		if(g==NULL) 
			flist_append(cl,0,(void *)sv_data);
		else 
			myflist_insert_before(cl,g,(void *)sv_data);
	}
	
	return cl;
		
}

static int uncook_reset(MAPI_UNUSED mapidflib_function_instance_t *instance) 
{
  return 0;
}

static int uncook_cleanup(MAPI_UNUSED mapidflib_function_instance_t *instance) 
{
  return 0;
}

struct uncook_data {
	struct cooking_data *flow;
	int fd;
};

static int uncook_init(MAPI_UNUSED mapidflib_function_instance_t *instance, MAPI_UNUSED int fd) {
	
  return 0;
}

static int uncook_instance(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd, MAPI_UNUSED mapidflib_flow_mod_t *flow_mod) {
	struct cooking_data *flow=NULL;
	struct uncook_data *data = NULL;
	mapidflib_function_instance_t *cook_instance = NULL;

	if((cook_instance=fhlp_get_function_instance_byname(instance->hwinfo->gflist, fd, "COOKING")) != NULL) {
		flow = (struct cooking_data*)cook_instance->internal_data;
	}
	
	data=(struct uncook_data *)malloc(sizeof(struct uncook_data));
	data->flow=flow;
	data->fd = fd;
	instance->internal_data=(void *)data;

  	return 0;
}

static int uncook_process(mapidflib_function_instance_t *instance,MAPI_UNUSED unsigned char* dev_pkt,unsigned char* link_pkt, mapid_pkthdr_t* pkt_head)  
{
	struct cooking_data *flow = NULL;
	struct uncook_data *data = NULL;
	
	data=(struct uncook_data *)(instance->internal_data);

	flow = data->flow;

	if(flow != NULL && flow->cooked == 1) {
		if(flow->client_headers || flow->server_headers) {
			flow->uncook_ready = 1;
			
			if(flow->decoded_packet!=NULL) {
				rebuild_fragments(instance,flow->client_headers,((mapipacket *)flow->decoded_packet)->data,flow->client_size, pkt_head, data->fd);	
			}
			else { 
				rebuild_fragments(instance,flow->client_headers,link_pkt,pkt_head->caplen, pkt_head, data->fd);	
			}
			
			flow->client_headers=merge_lists(flow->client_headers,flow->server_headers);
		}
	}

	return 1;
}

static mapidflib_function_def_t uncookfinfo={
  "", //libname
  "UNCOOK", //name
  "Splits the cooked packet into its original packets", //descr
  "iii", //argdescr
  MAPI_DEVICE_ALL, //devtype
  MAPIRES_NONE, //Method for returning results
  0, //shm size
  0, //modifies_pkts
  0, // filters_pkts
  MAPIOPT_AUTO, //Optimization
  uncook_instance, //instance
  uncook_init, //init
  uncook_process, //process
  NULL, //get_result,
  uncook_reset, //reset
  uncook_cleanup, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* uncook_get_funct_info();

mapidflib_function_def_t* uncook_get_funct_info() {
  return &uncookfinfo;
};


