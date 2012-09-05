#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/in.h>

#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "debug.h"
#include "expiredflowshash.h"

#define EXPIRED_FLOWS "EXPIRED_FLOWS"
#define TIMEOUT 30			//in epochs
#define EPOCHDURATION 1

#define ETHERTYPE_8021Q 0x8100
#define MPLS_MASK 0x8847
#define ETHERTYPE_IP 0x0800  /* IP protocol */


struct vlan_802q_header {
	u_int16_t priority_cfi_vid;
	u_int16_t ether_type;
};

pthread_t pthread;

typedef struct shm {
	unsigned int *size;
	flow_data *Table;
	pthread_mutex_t *smmutex;
}shm;


void add_toflow(struct exfl_data *data, eflow_data record, flows_stat *stats);
static struct exfl_hash_node *exfl_hash_lookup(unsigned int value, struct exfl_data *data, eflow_data record);
void exfl_add_to_hashtable_and_list(struct exfl_data *data, unsigned int value, eflow_data record);
void shift_node(struct exfl_data *data, struct exfl_list_node *node);
void poll_expired_flows(mapidflib_function_instance_t *instance);
void print_flow(eflow_data *data);

inline unsigned int hash_function(eflow_data record) {
	ip_addr saddr = record.saddr;
	ip_addr daddr = record.daddr;

	return ((unsigned int)((saddr.byte1 + saddr.byte2 + saddr.byte3 + saddr.byte4) * (record.sport + 1) +
		                     (daddr.byte1 + daddr.byte2 + daddr.byte3 + daddr.byte4) * (record.dport + 2))) / 137;
}

void add_toflow(struct exfl_data *data, eflow_data record, flows_stat *stats) {

	struct exfl_hash_node *lookup;
	unsigned int value = hash_function(record);

	pthread_mutex_lock( &(data->mutex) );

	lookup = exfl_hash_lookup(value, data, record);

	if(lookup == NULL) {
		pthread_mutex_unlock( &(data->mutex) );
		exfl_add_to_hashtable_and_list(data, value, record);
		stats->received++;
	}
	else {
		lookup->node->flow.packets_count++;
		lookup->node->flow.bytes_count += record.bytes_count;
		lookup->node->flow.epoch = data->epoch;

		shift_node(data, lookup->node);
		pthread_mutex_unlock( &(data->mutex) );
	}
	stats->packets.received++;
}

void shift_node(struct exfl_data *data, struct exfl_list_node *node) {
	struct exfl_list_node *previous;

	if( data->list_head == node)
		return;
	else {

		previous = node->previous;
		// remove node from list
		previous->next = node->next;
		if(node->next)
			node->next->previous = previous;
		else {
		//Tote node->next == NULL;
			data->list_tail = previous;
		}
		// Add node at the start of the list
		data->list_head->previous = node;
		node->next = data->list_head;
		node->previous = NULL;
		data->list_head = node;

	}
}

void exfl_add_to_hashtable_and_list(struct exfl_data *data, unsigned int value, eflow_data record) {

	struct exfl_list_node *newlistnode;
	struct exfl_hash_node *newhashnode;
	unsigned int pos;

	// Create a new list node
	if( (newlistnode = (struct exfl_list_node *)malloc(sizeof(struct exfl_list_node))) == NULL) {
		DEBUG_CMD(Debug_Message("Malloc failed for size %d", sizeof(struct exfl_list_node)));
		return;
	}
	newlistnode->value = value;
	newlistnode->flow = record;
	newlistnode->flow.packets_count = 1;
	newlistnode->next = newlistnode->previous = NULL;

	// Create a new hash node
	pos = value%EXFL_HASH_SIZE;
	if( (newhashnode = (struct exfl_hash_node *)malloc(sizeof(struct exfl_hash_node))) == NULL) {
		DEBUG_CMD(Debug_Message("Malloc failed for size %d", sizeof(struct exfl_hash_node)));
		return;
	}

	newhashnode->value = value;
	newhashnode->node = newlistnode;
	newhashnode->next = data->hashtable[pos];
	newhashnode->prev = NULL;

	//add to list
	pthread_mutex_lock( &(data->mutex) );

	data->list_size++;
	if(data->list_tail == NULL) {
		data->list_head = data->list_tail = newlistnode;
	}
	else {
		data->list_head->previous = newlistnode;
		newlistnode->next = data->list_head;
		data->list_head = newlistnode;
	}

	//add to hashtable
	if(data->hashtable[pos] != NULL)
		data->hashtable[pos]->prev = newhashnode;
	data->hashtable[pos] = newhashnode;

	pthread_mutex_unlock( &(data->mutex) );
}

int compare_ip(ip_addr ip1, ip_addr ip2)
{
	if ((ip1.byte1 == ip2.byte1) && (ip1.byte2 == ip2.byte2) && (ip1.byte3 == ip2.byte3) && (ip1.byte4 == ip2.byte4))
		return (1);
	return (0);
}


struct exfl_hash_node *exfl_hash_lookup(unsigned int value, struct exfl_data *data, eflow_data record) {
	unsigned int pos;
	struct exfl_hash_node *tmp;
	pos = value%EXFL_HASH_SIZE;
	tmp = data->hashtable[pos];
	eflow_data *hashflow;

	while(tmp) {
		if(tmp->value == value){
			hashflow = &(tmp->node->flow);
			if(record.ptcl == hashflow->ptcl ){
				if(compare_ip(record.saddr, hashflow->saddr) && compare_ip(record.daddr, hashflow->daddr)) {
					if((record.sport == hashflow->sport) && (record.dport == hashflow->dport)) return tmp;
				}
			}
		}
		tmp = tmp->next;
	}
	return(NULL);
}

int checkhash(struct exfl_hash_node **hashtable) {
	int i, count = 0;
	struct exfl_hash_node *tmp;

	for(i = 0; i < EXFL_HASH_SIZE; i++) {
		if(hashtable[i] != NULL) {
			tmp = hashtable[i];
			while(tmp != NULL) {
				count++;
				tmp = tmp->next;
			}
		}
	}
	return(count);
}

/*
 * Check if there are any records in expired flows list and put them
 * in shared memory if there is enough space.
 */
void check_expired_flows(struct exfl_data *data, shm shm_struct) {
	struct exfl_list_node *tmp, *tail = data->expired_flows_tail;

	while( (tail != NULL) && (*(shm_struct.size) != data->shm_flows) ) {
		// Add the expired flow directly into shared memory table
		pthread_mutex_lock( shm_struct.smmutex );
		memcpy(&(shm_struct.Table[*(shm_struct.size)]), &(tail->flow), sizeof(struct flow_data));
		(*(shm_struct.size))++;
		pthread_mutex_unlock( shm_struct.smmutex );
		// Remove node from the expired flows list
		data->expired_flows_list_size--;
		tmp = tail->previous;
		if(tmp != NULL)
			tmp->next = NULL;
		free(tail);
		tail = tmp;
	}

	if( tail == NULL ) {
		data->expired_flows_head = data->expired_flows_tail = NULL;
	}
	else
		data->expired_flows_tail = tail;
}


void poll_expired_flows(mapidflib_function_instance_t *instance) {
	struct exfl_data *data = instance->internal_data;
	struct exfl_list_node *tmp, *previous;
	struct exfl_hash_node *lookup_hash;
	eflow_data tmpeflow_data;
	flows_stat *stats;
	unsigned int value;
	pthread_mutex_t *mutex = &(data->mutex);
	int check;
	shm shm_struct;

	stats = (flows_stat *) instance->result.data;
	shm_struct.size = (unsigned int *)instance->result.data;
	shm_struct.Table = (flow_data *)((char *)instance->result.data+sizeof(flows_stat));
	shm_struct.smmutex = (pthread_mutex_t *)(((char *)instance->result.data) + sizeof(flows_stat) + sizeof(struct flow_data)*data->shm_flows);

	while(data->run) {
		pthread_testcancel();
		pthread_mutex_lock( mutex );
		tmp = data->list_tail;
		check_expired_flows(data, shm_struct);
		if(tmp) {	//if list is not empty
				while( data->epoch - tmp->flow.epoch > TIMEOUT) {
					stats->expired++;
					stats->packets.expired += tmp->flow.packets_count;
					previous = tmp->previous;
					value = tmp->value;
					tmpeflow_data = tmp->flow;

					//remove node from hashtable
					lookup_hash = exfl_hash_lookup(value, data, tmpeflow_data);
					if( lookup_hash != NULL) {
							if(data->hashtable[value%EXFL_HASH_SIZE] == lookup_hash) {
								data->hashtable[value%EXFL_HASH_SIZE] = lookup_hash->next;

								if( lookup_hash->prev != NULL ){
									DEBUG_CMD(Debug_Message("hash node is at the head, but previous isn't NULL"));
								}

								// lookup_hash->next is now at the head
								if( lookup_hash->next != NULL) {
									lookup_hash->next->prev = NULL;
								}
							}
							else {
								lookup_hash->prev->next = lookup_hash->next;
								if( lookup_hash->next != NULL)
									lookup_hash->next->prev = lookup_hash->prev;
							}
							free(lookup_hash);
					}
					else {
						DEBUG_CMD(Debug_Message("hash node not found but list node exist!"));
					}

					//remove node from list
					if(tmp->previous != NULL) {
						//the node isn't at the head.
						tmp->previous->next = NULL;
						data->list_tail = tmp->previous;
					}
					else {
						check = checkhash(data->hashtable);
						if( check != 1)
						data->list_head = NULL;
						data->list_tail = NULL;
					}
					/*
					* When the shared memory segment is full, expired flow records must
					* be removed from the temporal sorted list, because they are expired
					* and for a new packet of this flow, a new record must be created.
					* In order to achieve this we have a list with all the expired flow
					* records that couldn't be returned.
					*/

					if(*(shm_struct.size) == data->shm_flows) { // shm full
						//remove node from temporal sorted list
						if(tmp->next)
							tmp->next->previous = tmp->previous;
						if(tmp->previous)
							tmp->previous->next = tmp->next;

						// if packets_count is worth to add
						if(tmp->flow.valid && tmp->flow.packets_count >= ((struct exfl_data *)instance->internal_data)->packets_count_min) {
							if(data->expired_flows_list_size < data->expired_flows_list_size_max) { // if buffer not full
								//add node to expired flows list
								data->expired_flows_list_size++;
								if(data->expired_flows_head != NULL) {
									tmp->next = data->expired_flows_head;
									data->expired_flows_head->previous = tmp;
									tmp->previous = NULL;
									data->expired_flows_head = tmp;
								}
								else {
									data->expired_flows_head = data->expired_flows_tail = tmp;
									tmp->previous = tmp->next = NULL;
								}
							}
							else {
								// else drop
								stats->dropped++;
								stats->packets.dropped += tmp->flow.packets_count;
								free(tmp);
							}
						}
						else {
							stats->ignored++;
							stats->packets.ignored += tmp->flow.packets_count;
							free(tmp);
						}

					}
					else { // shm not full
						// if packets_count is worth to add
						if(tmp->flow.valid && tmp->flow.packets_count >= ((struct exfl_data *)instance->internal_data)->packets_count_min) {
							// Add the expired flow from temporal sorted list directly into shared memory table
							pthread_mutex_lock( shm_struct.smmutex );
							memcpy(&(shm_struct.Table[*(shm_struct.size)]), &(tmp->flow), sizeof(struct flow_data));
							(*(shm_struct.size))++;
							stats->packets.sent += tmp->flow.packets_count;
							pthread_mutex_unlock( shm_struct.smmutex );
						}
						else {
							stats->ignored++;
							stats->packets.ignored += tmp->flow.packets_count;
						}
						free(tmp);
					}

					data->list_size--;

					tmp = previous;
					if(tmp == NULL)
						break;
				}
		}
		pthread_mutex_unlock( mutex );
		sleep(EPOCHDURATION);
		data->epoch++;
	}
	pthread_exit(NULL);
}

static int exprflow_instance(mapidflib_function_instance_t *instance,
                             MAPI_UNUSED int fd,
                             MAPI_UNUSED mapidflib_flow_mod_t *flow_mod) {
	mapiFunctArg* fargs;
	int shm_flows; // max: (DIMAPI_DATA_SIZE - sizeof(flows_stat) - sizeof(mapi_results_t)) / sizeof(struct flow_data))

	fargs = instance->args;
	shm_flows = getargint(&fargs);

	instance->def->shm_size = sizeof(flows_stat) + sizeof(struct flow_data) * shm_flows + sizeof(pthread_mutex_t);

	// 0                 shm (instance->result.data)                             DIMAPI_DATA_SIZE
	// | mapi_result_type | flows_stat | shm_flows * flow_data | pthread_mutex_t |

	return 0;
}

static int exprflow_init(mapidflib_function_instance_t *instance, MAPI_UNUSED int fd)
{

	int mythread;
	pthread_mutex_t tmpmutex = PTHREAD_MUTEX_INITIALIZER;
	shm shm_struct;
	struct exfl_data *data;
	flows_stat *stats;

	mapiFunctArg* fargs;
	fargs = instance->args;

	// HashTable initialization
	if( (instance->internal_data = malloc(sizeof(struct exfl_data))) == NULL) {
		DEBUG_CMD(Debug_Message("Malloc failed for size %d", sizeof(struct exfl_data)));
		return(-1);
	}
	data = instance->internal_data;
	data->list_head = NULL;
	data->list_tail = NULL;
	data->expired_flows_head = NULL;
	data->expired_flows_tail = NULL;
	memset(data->hashtable, 0, EXFL_HASH_SIZE*sizeof(struct exfl_hash_node *));
	data->mutex = tmpmutex;
	data->run = 1;
	data->list_size = 0;
	data->expired_flows_list_size = 0;
	// Epoch initialization
	data->epoch=0;

	// function arguments
	data->shm_flows = getargint(&fargs); // max: (DIMAPI_DATA_SIZE - sizeof(flows_stat) - sizeof(mapi_results_t)) / sizeof(struct flow_data))
	data->expired_flows_list_size_max = getargint(&fargs);
	data->packets_count_min = getargint(&fargs);

	// Shared Memory Initialization
	stats = (flows_stat *)instance->result.data;
	shm_struct.size = (unsigned int *)instance->result.data;
	shm_struct.Table = (flow_data *)((char *)instance->result.data+sizeof(flows_stat));
	shm_struct.smmutex = (pthread_mutex_t *)(((char *)instance->result.data) + sizeof(flows_stat) + sizeof(struct flow_data) * data->shm_flows);

	stats->received = 0;
	stats->expired = 0;
	*(shm_struct.size) = 0; //stats->sent = 0;
	stats->ignored = 0;
	stats->dropped = 0;

	stats->packets.received = 0;
	stats->packets.expired = 0;
	stats->packets.sent = 0;
	stats->packets.ignored = 0;
	stats->packets.dropped = 0;

	//mutex initialization
	*(shm_struct.smmutex) = tmpmutex;

	// the thread pid is stored in internal_data in order to be available for stopping it in cleanup
	mythread = pthread_create(&((((struct exfl_data *)(instance->internal_data))->pthread)), NULL, (void *) &poll_expired_flows, (void *)instance);

	return 0;
}

static int exprflow_process(mapidflib_function_instance_t *instance, MAPI_UNUSED unsigned char* dev_pkt, unsigned char* link_pkt, mapid_pkthdr_t* pkt_head) {

	struct exfl_data *data = (struct exfl_data *)(instance->internal_data);
	struct flows_stat *stats;
	eflow_data record;
	ip_header* ip = NULL;
	tcp_header* tcp = NULL;
 	udp_header* udp = NULL;
	unsigned char *p = NULL;
	uint16_t ethertype;
	struct ether_header *ep = NULL;
	struct hdlc_header {
		uint8_t addr;     // 0x0F for unicast, 0x8F for broadcast
		uint8_t ctrl;     // 0x00
		uint16_t proto; // http://www.nethelp.no/net/cisco-hdlc.txt
	}	*hp = NULL;
	//int ether_len = 0;
	int ip_len = 0;
	unsigned int len = pkt_head->caplen;
	int headerlenoverplus = 0;

	stats = (flows_stat *) instance->result.data;

	struct vlan_802q_header *vlan_header;
	p = link_pkt;

	switch(instance->hwinfo->link_type) {
		case DLT_EN10MB:
				// lay the Ethernet header struct over the packet data
				ep = (struct ether_header *)p;
				//ether_len = sizeof(struct ether_header);

				// skip ethernet header
				p += sizeof(struct ether_header);
				len -= sizeof(struct ether_header);

				ethertype = ntohs(ep->ether_type);

				if(ethertype  == ETHERTYPE_8021Q) {
					vlan_header = (struct vlan_802q_header*)p;
					ethertype = ntohs(vlan_header->ether_type);
					p += sizeof(struct vlan_802q_header);
					headerlenoverplus = sizeof(struct vlan_802q_header);
				}

				if(ethertype == MPLS_MASK) {
					p += 4;
					headerlenoverplus = 4;
				}
				else if(ethertype != ETHERTYPE_IP) {
					DEBUG_CMD(Debug_Message("not an ip packet?"));
					return 0;
				}
			break;
		case DLT_CHDLC:
				hp = (struct hdlc_header *)p;

				p += sizeof(struct hdlc_header);
				len -= sizeof(struct hdlc_header);

				ethertype = ntohs(hp->proto);

				if (ethertype != ETHERTYPE_IP) {
					return 0;
				}
			break;
		default:
			//DEBUG_CMD(Debug_Message("Link layer not supported"));
			return 0;
	}

	// IP header struct over the packet data;
	ip =(ip_header*)p;
	ip_len = (ip->ver_ihl & 0xf) * 4;

	//IPPROTO_TCP
	if(ip->ptcl == IPPROTO_TCP){
		tcp = (tcp_header*)(p + ip_len);
		record.saddr = ip->saddr;
		record.daddr = ip->daddr;
		record.sport = ntohs(tcp->sport);
		record.dport = ntohs(tcp->dport);
		record.timestamp = pkt_head->ts;
		record.epoch = data->epoch;
		record.valid = data->epoch > TIMEOUT;
		record.ptcl = ip->ptcl;
		record.bytes_count = pkt_head->wlen - headerlenoverplus;
		record.ttl_pkt1 = ip->ttl;
		add_toflow(data, record, stats);
	}
	//IPPROTO_UDP
	else if( ip->ptcl == IPPROTO_UDP) {
		udp = (udp_header *)(p + ip_len);
		record.saddr = ip->saddr;
		record.daddr = ip->daddr;
		record.sport = ntohs(udp->sport);
		record.dport = ntohs(udp->dport);
		record.timestamp = pkt_head->ts;
		record.epoch = data->epoch;
		record.valid = data->epoch > TIMEOUT;
		record.ptcl = ip->ptcl;
		record.bytes_count = pkt_head->wlen - headerlenoverplus;
		record.ttl_pkt1 = ip->ttl;
		add_toflow(data, record, stats);
	}
	//IPPROTO_IP
	else {
		record.saddr = ip->saddr;
		record.daddr = ip->daddr;
		record.sport = record.dport = ntohs(0);
		record.timestamp = pkt_head->ts;
		record.epoch = data->epoch;
		record.valid = data->epoch > TIMEOUT;
		record.ptcl = ip->ptcl;
		record.bytes_count = pkt_head->wlen - headerlenoverplus;
		record.ttl_pkt1 = ip->ttl;
		add_toflow(data, record, stats);
	}
	return 1;
}

static int exprflow_reset(MAPI_UNUSED mapidflib_function_instance_t *instance)
{
	// empty HashTable?
  return 0;
}

static int exprflow_cleanup(mapidflib_function_instance_t *instance)
{
	struct exfl_list_node *tmp = ((struct exfl_data *)(instance->internal_data))->list_head;
	struct exfl_list_node *next;
	struct exfl_hash_node *tmphash, *nexthash;
	int i = EXFL_HASH_SIZE, count=0;


	// stop polling thread
	pthread_cancel((((struct exfl_data *)(instance->internal_data))->pthread));
	//fprintf(stderr, "Hashtable contains %d buckets\n", checkhash(((struct exfl_data *)(instance->internal_data))->hashtable));
	// HashTable deallocation
	while( i-- > 0 ) {
		tmphash = ((struct exfl_data *)(instance->internal_data))->hashtable[i];
		while(tmphash != NULL) {
			//fprintf(stderr, "Cleaning hash node %p\n", tmphash);
			//print_flow(&(tmphash->node->flow));

			nexthash = tmphash->next;
			free(tmphash);
			tmphash = nexthash;
		}
	}
	// List deallocation
	while(tmp != NULL) {
		//fprintf(stderr, "Cleaning list node %p\n", tmp);
		//print_flow(&(tmp->flow));
		next = tmp->next;
		free(tmp);
		tmp = next;
		count++;
	}
	count = 0;
	// Exprired Flows list deallocation
	tmp = ((struct exfl_data *)(instance->internal_data))->expired_flows_head;
	while(tmp != NULL) {
		next = tmp->next;
		free(tmp);
		tmp = next;
		count++;
	}

	free(instance->internal_data);

	return 0;
}

void print_flow(eflow_data *data) {
	switch (data->ptcl) {
		case IPPROTO_TCP: fprintf(stdout, "TCP "); break;
		case IPPROTO_UDP: fprintf(stdout, "UDP "); break;
		default: fprintf(stdout, "IP "); break;
	}

	fprintf(stdout, "src %d.%d.%d.%d:%d\t", data->saddr.byte1, data->saddr.byte2, data->saddr.byte3, data->saddr.byte4, data->sport);
	fprintf(stdout, "dst %d.%d.%d.%d:%d\t", data->daddr.byte1, data->daddr.byte2, data->daddr.byte3, data->daddr.byte4, data->dport);
	fprintf(stdout, "packets: %lld, bytes: %lld\n", data->packets_count, data->bytes_count);
}

static int exprflow_client_read_result(mapidflib_function_instance_t *instance,mapi_result_t *res) {
	shm shm_struct;
	flows_stat *stats;

	mapiFunctArg* fargs;
	int shm_flows; // max: (DIMAPI_DATA_SIZE - sizeof(flows_stat) - sizeof(mapi_results_t)) / sizeof(struct flow_data))

	fargs = instance->args;
	shm_flows = getargint(&fargs);

	stats = (flows_stat *)instance->result.data;
	shm_struct.size = (unsigned int *)instance->result.data;
	shm_struct.Table = (flow_data *)((char *)instance->result.data+sizeof(flows_stat));
	shm_struct.smmutex = (pthread_mutex_t *)(((char *)instance->result.data) + sizeof(flows_stat) + sizeof(struct flow_data) * shm_flows);

	res->res = instance->internal_data;
	res->size = sizeof(flows_stat) + sizeof(flow_data) * (*(shm_struct.size));

	pthread_mutex_lock( shm_struct.smmutex );
	memcpy(instance->internal_data, instance->result.data, res->size);
	stats->received = 0;
	stats->expired = 0;
	*(shm_struct.size) = 0; //stats->sent = 0;
	stats->ignored = 0;
	stats->dropped = 0;
	stats->packets.received = 0;
	stats->packets.expired = 0;
	stats->packets.sent = 0;
	stats->packets.ignored = 0;
	stats->packets.dropped = 0;
	pthread_mutex_unlock( shm_struct.smmutex );

	return(0);
}

static int exprflow_client_init( mapidflib_function_instance_t *instance, void *data) {

	mapiFunctArg* fargs;
	int shm_flows; // max: (DIMAPI_DATA_SIZE - sizeof(flows_stat) - sizeof(mapi_results_t)) / sizeof(struct flow_data))

	fargs = instance->args;
	shm_flows = getargint(&fargs);

	if(shm_flows > (DIMAPI_DATA_SIZE - sizeof(flows_stat) - sizeof(mapi_results_t)) / sizeof(struct flow_data)) {
		printf("Cannot process %d flows. Maximum is %d.\n", shm_flows, (DIMAPI_DATA_SIZE - sizeof(flows_stat) - sizeof(mapi_results_t)) / sizeof(struct flow_data));
		return(-1);
	}

	if((instance->internal_data = malloc(sizeof(flows_stat)+sizeof(struct flow_data)*shm_flows)) == NULL) {
		printf("Malloc failed for size %d [%s:%d]\n", sizeof(flows_stat)+sizeof(struct flow_data)*shm_flows, __FILE__, __LINE__);
		return(-1);
	}
	data = instance->internal_data;
	return(0);
}

/* This function is called when the ﬂow closes and should release all resources
 * allocated by the EXPIRED_FLOWS function on the client side */

static int exprflow_client_cleanup( mapidflib_function_instance_t *instance){

	free(instance->internal_data);
	return(0);
}

static mapidflib_function_def_t finfo={
  "", //libname
  EXPIRED_FLOWS, //name
  "Expired Flows function", //descr
  "iii", //argdescr
  MAPI_DEVICE_ALL, //devtype
  MAPIRES_SHM, //Method for returning results
  0, //shm size. Set by instance.
  0, //modifies_pkts
  0, //filters packets ?
  MAPIOPT_NONE,
  exprflow_instance, //instance
  exprflow_init, //init
  exprflow_process, //process
  NULL, //get_result,
  exprflow_reset, //reset
  exprflow_cleanup, //cleanup
  exprflow_client_init, //client_init
  exprflow_client_read_result, //client_read_result
  exprflow_client_cleanup //client_cleanup
};

mapidflib_function_def_t* exprflow_get_funct_info();

mapidflib_function_def_t* exprflow_get_funct_info() {
  return &finfo;
};
