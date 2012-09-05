#define EXFL_HASH_SIZE 262144 //4128

#include "protocols.h"

typedef struct eflow_data {
	unsigned long long timestamp;
	unsigned long long packets_count, bytes_count;
	ip_addr saddr, daddr;
	u_short sport, dport;
	u_char ptcl;
	u_char ttl_pkt1;
	unsigned long long epoch;
	unsigned int valid;
} eflow_data;

typedef struct flow_data {
	unsigned long long timestamp;
	unsigned long long packets_count, bytes_count;
	ip_addr saddr, daddr;
	u_short sport, dport;
	u_char ptcl;
	u_char ttl_pkt1;
} flow_data;

typedef struct flows_stat {
	unsigned int sent;
	unsigned int received;
	unsigned int expired;
	unsigned int ignored;
	unsigned int dropped;
	struct {
		unsigned int sent;
		unsigned int received;
		unsigned int expired;
		unsigned int ignored;
		unsigned int dropped;
	} packets;
} flows_stat;

struct exfl_list_node {

	unsigned int value;

	/* info that define a flow */
	struct eflow_data flow;

	struct exfl_list_node *next;
	struct exfl_list_node *previous;
};


struct exfl_hash_node {
	unsigned int value;
	struct exfl_list_node *node;
	struct exfl_hash_node *next;
	struct exfl_hash_node *prev;

};

struct exfl_data {
	int list_size;
	unsigned int expired_flows_list_size;
	unsigned int expired_flows_list_size_max;
	struct exfl_list_node *list_head;
	struct exfl_list_node *list_tail;
	struct exfl_hash_node *hashtable[EXFL_HASH_SIZE];
	struct exfl_list_node *expired_flows_head;
	struct exfl_list_node *expired_flows_tail;
	pthread_mutex_t mutex;
	pthread_t pthread;
	unsigned int run;
	unsigned long long epoch;
	unsigned int packets_count_min;
	unsigned int shm_flows;
};
