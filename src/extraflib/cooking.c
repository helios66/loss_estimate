#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pcap.h>
#include <sys/shm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <nids.h>

#include "mapi.h"
#include "mapi_errors.h"
#include "debug.h"
#include "mapid.h"
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "fhelp.h"
#include "cooking.h"
#include "pcapio.h"

#define int_ntoa(x) inet_ntoa(*((struct in_addr *)&x))



void create_mod_pkt(unsigned char *dev_pkt,struct cooking_data *flow,mapid_pkthdr_t *pkt_head);
void mapi_tcp_callback(struct tcp_stream *ns, MAPI_UNUSED void **param);

struct tcp_flow_data {
	struct cooking_data *flow;
	int discard;
};

static int nids_not_inited=1;

static struct tcp_stream *mapi_find_stream(struct tcphdr * this_tcphdr, 
			struct ip * this_iphdr, int *from_client) {
	struct tuple4 this_addr, reversed;
	struct tcp_stream *a_tcp;

	this_addr.source = ntohs(this_tcphdr->source);
	this_addr.dest = ntohs(this_tcphdr->dest);
	this_addr.saddr = this_iphdr->ip_src.s_addr;
	this_addr.daddr = this_iphdr->ip_dst.s_addr;
	a_tcp = nids_find_tcp_stream(&this_addr);
	if (a_tcp) {
		*from_client = 1;
		return a_tcp;
	}
	reversed.source = ntohs(this_tcphdr->dest);
	reversed.dest = ntohs(this_tcphdr->source);
	reversed.saddr = this_iphdr->ip_dst.s_addr;
	reversed.daddr = this_iphdr->ip_src.s_addr;
	a_tcp = nids_find_tcp_stream(&reversed);
	if (a_tcp) {
		*from_client = 0;
		return a_tcp;
	}
	return 0;
}

static int cook_instance(mapidflib_function_instance_t* instance,MAPI_UNUSED  int fd, MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
	struct cooking_data* data = NULL; 
	mapiFunctArg* fargs;

	data = (struct cooking_data*)malloc(sizeof(struct cooking_data));
	memset(data, 0, sizeof(struct cooking_data));
	
	fargs = instance->args;
	data->threshold = getargint(&fargs);
	data->timeout = getargint(&fargs);
	data->ret_once = getargint(&fargs);
	data->collect = getargint(&fargs);

	if (data->collect != SERVER_SIDE && data->collect != CLIENT_SIDE
		 && data->collect != BOTH_SIDE) {
		return MFUNCT_INVALID_ARGUMENT_4;
	}

	instance->internal_data=data;

	return 0;
}

static int cook_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{
	struct cooking_data *data;

	if (nids_not_inited) {
		pcap_t *desc;
		struct nids_chksum_ctl *nochksumchk;

		desc = malloc(sizeof(pcap_t));
		desc->fd = 1;
		desc->linktype = instance->hwinfo->link_type;
		desc->bufsize = instance->hwinfo->cap_length;

		nids_params.pcap_desc = desc;
		nids_params.tcp_workarounds = 1;

		/* disable checksum checking for all packets */
		nochksumchk = malloc(sizeof(struct nids_chksum_ctl));
		nochksumchk->netaddr = 0;
		nochksumchk->mask = 0;
	    nochksumchk->action = NIDS_DONT_CHKSUM;
		nids_register_chksum_ctl(nochksumchk, 1);

		if (!nids_init()) {
			DEBUG_CMD(Debug_Message("NIDS Error: %s", nids_errbuf));
			return -1;
		}

		nids_register_tcp(mapi_tcp_callback);
		nids_not_inited = 0;
	}

	data = (struct cooking_data *)(instance->internal_data);


/*	//check if uncook is applied
	functs = flist_get(instance->hwinfo->gflist->fflist, fd);
	for (fid=1; (funct=flist_get(functs, fid)); fid++) {
	    if (!strcmp(funct->instance->def->name, "UNCOOK"))
		data->keep_headers = 1;
	}
*/
	//printf("Cooking : %s keeping headers %d \n", (data->keep_headers)?"":"NOT", fd);

	if (data->threshold <= 0) {
	    data->threshold = 32000; //default value 32K
	}

	if (data->threshold < 1600) 
	    instance->hwinfo->cap_length = 1600;
	else 
	    instance->hwinfo->cap_length = data->threshold + 100;//+100 for headers


	data->ret_client_data = malloc(sizeof(char) * data->threshold);
	data->ret_server_data = malloc(sizeof(char) * data->threshold);
	data->client_ready = 0;
	data->server_ready = 0;
	

	//data->ni = nids_mapi_init(&desc, instance->hwinfo->link_type);
	//data->ni = nids_create();

	return 0;
}


void create_mod_pkt(unsigned char *link_pkt,struct cooking_data *flow,mapid_pkthdr_t *pkt_head) {
	
	unsigned char *ret_data;
	unsigned int ret_size;
	ether_header* eth = NULL;
	ip_header* ip = NULL;
	tcp_header* tcp = NULL;
	int ether_len = 0, ip_len = 0, tcp_len = 0;

	eth = (ether_header*)link_pkt;
	ether_len = sizeof(ether_header);
	ip = (ip_header*)(link_pkt + ether_len);
	ip_len = (ip->ver_ihl & 0xf) * 4;
	
	tcp = (tcp_header*)(link_pkt + ether_len + ip_len);
	tcp_len = tcp->off * 4;
	tcp->seq = 0;

	if (flow->client_ready && flow->server_ready && flow->collect != BOTH_SIDE) {
	    DEBUG_CMD(Debug_Message("client and server are ready but we dont collect both"));
	}

	if (flow->client_ready) {
	    ret_data = flow->ret_client_data;
	    ret_size = flow->client_size;
	}
	else {
	    ret_data = flow->ret_server_data;
	    ret_size = flow->server_size;
	}

	if (ret_size > (unsigned int)flow->threshold){
	    DEBUG_CMD(Debug_Message("Packet size is greater than Threshold : %d", ret_size - flow->threshold));
	}

	ip->tlen = ntohs(ret_size + ip_len + tcp_len);
	
	//fprintf(stderr, "flow->mod_pkt_size old %d new %d\n", flow->mod_pkt_size, (sizeof(char) * (ret_size +ether_len + ip_len + tcp_len)));
/* DEL	
	if (flow->mod_pkt_size < (sizeof(char)*(ret_size + ether_len + ip_len + tcp_len))) {
		flow->mod_pkt = realloc(flow->mod_pkt,(sizeof(char)*(ret_size + ether_len + ip_len + tcp_len)));
		flow->mod_pkt_size = (sizeof(char) * (ret_size + ether_len + ip_len + tcp_len));
	}
*/
//	memset(link_pkt, 0, (sizeof(char) * (ret_size + ether_len + ip_len + tcp_len)));
//	memcpy(link_pkt, eth, ether_len);
//	memcpy(&link_pkt[ether_len], ip, ip_len);
//	memcpy(&link_pkt[ether_len + ip_len], tcp, tcp_len);	
	memcpy(&link_pkt[ether_len + ip_len + tcp_len], ret_data, ret_size);

	//flow->client_headers = flow->ret_client_headers;
	//flow->server_headers = flow->ret_server_headers;

	pkt_head->caplen = pkt_head->wlen = ret_size + ether_len + ip_len + tcp_len;

//DEL	memcpy(link_pkt, flow->mod_pkt, pkt_head->caplen);
	flow->cooked = 1;
	//printf("create_mod_pkt: pkt_head->caplen: %d\n", pkt_head->caplen);
}

void mapi_tcp_callback(struct tcp_stream *a_tcp, MAPI_UNUSED void **param)
{
	struct tcp_flow_data *td = a_tcp->user;
	struct cooking_data *flow = td->flow;

	//printf("tcp_callback : ");

	if (a_tcp->nids_state == NIDS_JUST_EST) {
	    //fprintf(stderr, "callback: established\n");
	    switch (flow->collect) {
		case SERVER_SIDE:
		    a_tcp->server.collect++;
		    a_tcp->client.collect--;
		    break;
		case CLIENT_SIDE:
		    a_tcp->client.collect++;
		    a_tcp->server.collect--;
		    break;
		case BOTH_SIDE:
		    a_tcp->server.collect++;
		    a_tcp->client.collect++;
		    break;
		default:
		    ;
	    }
		//printf("callback: just established\n");
	    return;
	}
	
	if (a_tcp->nids_state == NIDS_DATA) {
	//	printf("data\n");
	    struct half_stream *hlf;
	    //flist_t **heads;
	    unsigned char **ret_data;
	    unsigned int *ret_size;
	    int *ready;

	    if (a_tcp->client.count_new) {
			hlf = &a_tcp->client;
			//heads = &flow->ret_client_headers;
			ret_data = &flow->ret_client_data;
			ret_size = &flow->client_size;
			ready = &flow->client_ready;
			if (flow->collect == SERVER_SIDE)
		    	DEBUG_CMD(Debug_Message("Asked for server data but got client's"));
	    }
	    else {
			hlf = &a_tcp->server;
			//heads = &flow->ret_server_headers;
			ret_data = &flow->ret_server_data;
			ret_size = &flow->server_size;
			ready = &flow->server_ready;
			if (flow->collect == CLIENT_SIDE)
		    	DEBUG_CMD(Debug_Message("Asked for client data but got server's"));
	    }

	    if (td->discard) {
			return;
	    }

	    if (hlf->count - hlf->offset >= flow->threshold) { //we have enough data
		//*heads = hlf->headers;
			memcpy(*ret_data, hlf->data, flow->threshold);
			*ret_size = flow->threshold;
			*ready = 1;
			nids_discard(a_tcp, flow->threshold);
			if (flow->ret_once)
		    	td->discard = 1;
	    }
	    else { //keep them
			nids_discard(a_tcp, 0);
	    }
	    return;
	}

	if (a_tcp->nids_state == NIDS_CLOSE || a_tcp->nids_state == NIDS_RESET || a_tcp->nids_state == NIDS_TIMED_OUT || a_tcp->nids_state == NIDS_EXITING) {
	    int server_bytes, client_bytes;

		//printf("call_back: close\n");
	    
	    //flow->ret_server_headers = a_tcp->server.headers;
	    //flow->ret_client_headers = a_tcp->client.headers;
	    server_bytes = a_tcp->server.count - a_tcp->server.offset;
	    client_bytes = a_tcp->client.count - a_tcp->client.offset;
	    
	    if (server_bytes > 0 && flow->collect != CLIENT_SIDE) {
			//flow->ret_server_data = malloc(sizeof(unsigned char) * server_bytes);
			memcpy(flow->ret_server_data, a_tcp->server.data, flow->threshold);
			flow->server_size = server_bytes;
			flow->server_ready = 1;
	    }

	    if (client_bytes > 0 && flow->collect != SERVER_SIDE) {
		//flow->ret_client_data = malloc(sizeof(unsigned char) * client_bytes);
			memcpy(flow->ret_client_data, a_tcp->client.data, flow->threshold);
			flow->client_size = client_bytes;
			flow->client_ready = 1;
	    }
	}
}

static int cook_process(mapidflib_function_instance_t *instance,MAPI_UNUSED unsigned char* dev_pkt,unsigned char* link_pkt, mapid_pkthdr_t* pkt_head)
{
    struct pcap_pkthdr h;
    ether_header* eth = NULL;
    struct ip *iph = NULL;
    struct tcphdr *tcph = NULL;
    int ether_len = 0, ip_len = 0, from_client=0;
    struct cooking_data *flow=NULL, *streams_flow=NULL;
    struct tcp_stream *stream=NULL;
	
    eth = (ether_header*)link_pkt;
    ether_len = sizeof(ether_header);
    iph = (struct ip*)(link_pkt + ether_len);
    ip_len = (iph->ip_hl & 0xf) * 4;

    if(iph->ip_p != IPPROTO_TCP) {	// no TCP packet
    	return 1;
    }

	//printf("Cook process");

	tcph = (struct tcphdr *)(link_pkt + ether_len + ip_len);

	flow = (struct cooking_data*)(instance->internal_data);
	flow->server_ready = 0;
	flow->client_ready = 0;
	flow->client_size = flow->server_size = 0;

	h.caplen = pkt_head->caplen;
	h.len = pkt_head->wlen;
	h.ts.tv_sec = pkt_head->ts; //XXX
	h.ts.tv_usec = pkt_head->ts;

	//find the stream before pcap_handler
	stream = mapi_find_stream(tcph, iph, &from_client);

	if (stream != NULL) {
		streams_flow = ((struct tcp_flow_data *)stream->user)->flow;
	}

    nids_pcap_handler(NULL, &h, link_pkt);

	//find the right stream
	stream = mapi_find_stream(tcph, iph, &from_client);
	
	if (stream != NULL) {
		if (stream->client.state == TCP_SYN_SENT && stream->server.state == TCP_CLOSE) {
			//new connection, not established
			struct tcp_flow_data *td = malloc(sizeof (struct tcp_flow_data));
			td->discard = 0;
			td->flow = flow;
			stream->user = td;
		}
		streams_flow = ((struct tcp_flow_data *)stream->user)->flow;
	}

	
/* XXX later .....

	if (stream->client.headers == NULL && stream->server.headers == NULL) { //new stream. not established
	    if (flow->keep_headers) {
		stream->client.headers = (flist_t *)malloc(sizeof(flist_t));
		flist_init(stream->client.headers);
		stream->server.headers = (flist_t *)malloc(sizeof(flist_t));
		flist_init(stream->server.headers);
	    }
	    stream->flow = (void *)flow;
	    stream->discard = 0;
	    //fprintf(stderr, "cook_process: flow assigned %s\n", adres(stream->addr));
	}

	if (flow->keep_headers) {

	    if (from_client)
		hlf = &stream->client;
	    else
		hlf = &stream->server;
	
	    curr_head = malloc(sizeof(struct headers_data));
	    curr_head->header = malloc(pkt_head->caplen); //added 100 more bytes
	    memcpy(curr_head->header, link_pkt, pkt_head->caplen);
	    curr_head->caplen = pkt_head->caplen;
	    curr_head->wlen = pkt_head->wlen;
	    curr_head->ts.tv_sec = pkt_head->ts; //XXX
	    curr_head->ts.tv_usec = pkt_head->ts;

	    assert(hlf->headers);
	    flist_append(hlf->headers, hlf->pkt_count++, (void*)curr_head);
	}
*/
	if ((flow->client_ready || flow->server_ready) && streams_flow == flow) {
	    // Set pseudoheader and new cooked packet to return to the daemon
	    create_mod_pkt(link_pkt,flow,pkt_head);
		return 1;
	}
	return 0;
}

//////////////////////////////////////////////

static int cook_cleanup(MAPI_UNUSED mapidflib_function_instance_t *instance)
{
    struct cooking_data *flow = (struct cooking_data *)(instance->internal_data);
   	 
    //DEL free(flow->mod_pkt);
    free(flow->ret_client_data);
    free(flow->ret_server_data);
	//free(flow->ni->nids_params.pcap_desc);
	//nids_exit(flow->ni);
    free(flow);

    return 0;
}

//////////////////////////////////////////////

static mapidflib_function_def_t cooking_finfo =
{
	"", //libname
	"COOKING", //name
	"Cooking TCP/IP packets", //Description
	"iiii", //argdescr
	MAPI_DEVICE_ALL, //Devoid
	MAPIRES_NONE,
	0, //shm size
	1, //modifies_pkts
	0, //filters packets
	MAPIOPT_AUTO,
	cook_instance, //instance
	cook_init, //init
	cook_process, //process
	NULL, //get_result,
	NULL, //reset
	cook_cleanup, //cleanup
	NULL, //client_init
	NULL, //client_read_result
	NULL  //client_cleanup
};

mapidflib_function_def_t* cooking_get_funct_info();

mapidflib_function_def_t* cooking_get_funct_info()
{
	return &cooking_finfo;
};
