#ifndef _TRACK_FTP
#define _TRACK_FTP

#define METHOD_PASV 1
#define METHOD_PORT 2

struct extract_res {
	unsigned int address;
	unsigned short port;
	char method;
};

typedef struct _track_ftp_results
{
	unsigned long long total_pkt_count;
	unsigned long long total_byte_count;
	list_t *filters;
} track_ftp_results;

struct extract_filter {
	char method;
	unsigned int address1;
	unsigned short port1;
	unsigned int address2;
	unsigned short port2;
};

int extract_ports(char *, int, struct extract_res *);
void add_to_list(flist_t *,char, unsigned int, unsigned short, unsigned int, unsigned short);
#endif
