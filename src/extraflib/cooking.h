#ifndef _COOK_H_
#define _COOK_H_

#include "mapidlib.h"
#include "protocols.h"

typedef unsigned char byte;

struct cooking_data
{
	// cooking args
	int threshold;
	int timeout;
	int ret_once;
	enum cooking_direction collect;

	/* DEL
	mapid_pkthdr_t *mod_pkt_head;
	unsigned char *mod_pkt;
	unsigned int mod_pkt_size;
	*/

	unsigned char *server_mod_pkt;
	mapid_pkthdr_t server_mod_pkt_head;
	flist_t *client_headers;
	flist_t *server_headers;
	unsigned int client_size;
	unsigned int server_size;
	flist_t *ret_client_headers;
	flist_t *ret_server_headers;
	unsigned char* ret_client_data;
	unsigned char* ret_server_data;
	int client_ready;
	int server_ready;

	char keep_headers;
	//shared (uncook)
	char uncook_ready;
	void *decoded_packet;
	char cooked;
};

struct headers_data {
	unsigned char *header;
	int header_len;
	unsigned int caplen;
	unsigned int wlen;
	struct timeval ts;
	void *decoded_pkt;
};

/////////////////////////////////////////////////////////////////////
#endif	//_COOK_H_
