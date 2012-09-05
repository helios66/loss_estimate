#define TOPX_HASH_SIZE 4096
#define TOPX_MAX_X 1000

#include <netinet/ip6.h>

struct topx_val {
	unsigned int val[4];
	unsigned char len; /* len == 1 || len == 4 */
};

struct topx_list_node {
	struct topx_val value;
	unsigned int count;
	unsigned long long bytecount;
	unsigned int last_rst_secs;
	struct topx_list_node *next;
	struct topx_list_node *previous;
};

struct topx_result {
	unsigned int value;
	struct in6_addr addr6;
	sa_family_t family;
	unsigned int count;
	unsigned long long bytecount;
	unsigned int last_rst_secs;
};


struct topx_hash_node {
	struct topx_val value;
	struct topx_list_node *node;
	struct topx_hash_node *next;
};

struct topx_data {
	int x;
	int protocol;
	int field;
	int list_size;
	int sortby;
	unsigned int reset_interval;
	unsigned int previous_reset;
	unsigned int last_rst;
	struct topx_list_node *list_head;
	struct topx_list_node *list_tail;
	struct topx_hash_node *hashtable[TOPX_HASH_SIZE];
	
};

#define TOPX_IP    1
#define TOPX_TCP   2
#define TOPX_UDP   3
#define TOPX_ICMP  4

typedef enum {
	TOPX_IP_TOS=1,
	TOPX_IP_LENGTH,
	TOPX_IP_ID,
	TOPX_IP_OFFSET,
	TOPX_IP_TTL,
	TOPX_IP_PROTOCOL,
	TOPX_IP_CHECKSUM,
	TOPX_IP_SRCIP,
	TOPX_IP_DSTIP,
	TOPX_TCP_SRCPORT,
	TOPX_TCP_DSTPORT,
	TOPX_TCP_SEQ,
	TOPX_TCP_ACK,
	TOPX_TCP_FLAGS,
 	TOPX_TCP_WIN,
	TOPX_TCP_CRC,
	TOPX_TCP_URGENT,
	TOPX_UDP_SRCPORT,
	TOPX_UDP_DSTPORT,
	TOPX_UDP_LENGTH,
	TOPX_UDP_CHECKSUM		
} topxDefs;

#define SORT_BY_PACKETS 1
#define SORT_BY_BYTES   2
