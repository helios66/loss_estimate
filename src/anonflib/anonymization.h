#ifndef _ANONYMIZATION_H_
#define _ANONYMIZATION_H_

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <pcap.h>
#include "anon_snort_decode.h"

#define MAX_UPPER_PROTOCOLS 10

typedef struct _mapiPacket
{
    struct pcap_pkthdr *pkth;   /* BPF data */
    unsigned char *pkt;              /* base pointer to the raw packet data */

    Fddi_hdr *fddihdr;          /* FDDI support headers */
    Fddi_llc_saps *fddisaps;
    Fddi_llc_sna *fddisna;
    Fddi_llc_iparp *fddiiparp;
    Fddi_llc_other *fddiother;
    Trh_hdr *trh;               /* Token Ring support headers */
    Trh_llc *trhllc;
    Trh_mr *trhmr;
    SLLHdr *sllh;               /* Linux cooked sockets header */
    PflogHdr *pfh;              /* OpenBSD pflog interface header */
    EtherHdr *eh;               /* standard TCP/IP/Ethernet/ARP headers */
    VlanTagHdr *vh;
    EthLlc   *ehllc;
    EthLlcOther *ehllcother;
    WifiHdr *wifih;         /* wireless LAN header */
    EtherARP *ah;
    EtherEapol *eplh;       /* 802.1x EAPOL header */
    EAPHdr *eaph;
    unsigned char *eaptype;
    EapolKey *eapolk;

    IPHdr *iph, *orig_iph;   /* and orig. headers for ICMP_*_UNREACH family */
    unsigned int ip_options_len;
    unsigned char *ip_options_data;

    struct ip6_hdr *ip6h, *orig_ip6h;    /* IPv6 specific stuff */
    struct ip6_frag *ip6fh;
    struct icmp6_hdr *icmp6h;
    
    TCPHdr *tcph, *orig_tcph;
    unsigned int tcp_options_len;
    unsigned char *tcp_options_data;

    UDPHdr *udph, *orig_udph;
    ICMPHdr *icmph, *orig_icmph;

    echoext *ext;       /* ICMP echo extension struct */

    unsigned char *ipdata;     /* IP payload pointer (incl tcp/udp header) */
    unsigned char *data;     /* packet payload pointer */
    unsigned short int ipdsize;        /* IP payload size */
    unsigned short int dsize;        /* packet payload size */
    unsigned short int alt_dsize; /* the dsize of a packet before munging
                            (used for log)*/

    unsigned char frag_flag;     /* flag to indicate a fragmented packet */
    unsigned short int frag_offset;  /* fragment offset number */
    unsigned char mf;            /* more fragments flag */
    unsigned char df;            /* don't fragment flag */
    unsigned char rf;                  /* IP reserved bit */

    unsigned short int sp;       /* source port (TCP/UDP) */
    unsigned short int dp;       /* dest port (TCP/UDP) */
    unsigned short int orig_sp;      /* source port (TCP/UDP) of original datagram */
    unsigned short int orig_dp;      /* dest port (TCP/UDP) of original datagram */
    unsigned int caplen;

    unsigned char uri_count;   /* number of URIs in this packet */

#define MAX_IPV6_OPT 40
    IPV6Opt ip6_options[MAX_IPV6_OPT]; /* IPV6 Option Header decode structure */
    u_int32_t ip6_option_count;  /* number of Option Header in this packet */
    
    Options ip_options[40]; /* ip options decode structure */
    unsigned int ip_option_count;  /* number of options in this packet */
    u_char ip_lastopt_bad;  /* flag to indicate that option decoding was halted due to a bad option */
    Options tcp_options[40];    /* tcp options decode struct */
    unsigned int tcp_option_count;
    u_char tcp_lastopt_bad;  /* flag to indicate that option decoding was halted due to a bad option */

    unsigned char csum_flags;        /* checksum flags */
    unsigned int packet_flags;     /* special flags for the packet */

	void *upper_layer_protocol_headers[MAX_UPPER_PROTOCOLS];
	int upper_layer_names[MAX_UPPER_PROTOCOLS];
	int num_of_upper_layer_protocols;

} mapipacket;

typedef enum {
	INTEGER,
	STR
} patternTypes;


typedef enum  {
		
	//ACCEPTED PROTOCOLS
	IP=1  ,
	TCP  ,
	UDP  ,
	ICMP ,
	HTTP ,
	FTP  ,
	
	
	//ANONYMIZATION FUNCTIONS
	UNCHANGED         , 
	MAP               ,
	MAP_DISTRIBUTION  ,
	STRIP             ,
	RANDOM            ,
	HASHED            ,
	PATTERN_FILL      ,
	ZERO              ,
	REPLACE           ,
	PREFIX_PRESERVING ,
	PREFIX_PRESERVING_MAP ,
	CHECKSUM_ADJUST   ,
	FILENAME_RANDOM   ,
	REGEXP            ,
	
	PAD_WITH_ZERO     ,
	STRIP_REST        ,
	
	//ACCEPTABLE HASH FUNCTIONS
	ANON_SHA              ,
	ANON_MD5              ,
	ANON_CRC32            ,
	ANON_SHA_2		 ,
	ANON_TRIPLEDES   	 ,
	ANON_AES		 ,
	ANON_DES              ,
	
	BASE_FIELD_DEFS,
	PAYLOAD, //common to all protocols
	CHECKSUM,
	SRC_IP,
	DST_IP,
	TTL,
	TOS,
	ID,
	FIELD_VERSION,
	OPTIONS,
	PACKET_LENGTH,
	IP_PROTO,
	IHL,
	FRAGMENT_OFFSET ,
	
	SRC_PORT ,
	DST_PORT ,
	SEQUENCE_NUMBER,
	OFFSET_AND_RESERVED,
	ACK_NUMBER,
	FLAGS ,
	URGENT_POINTER,
	WINDOW ,
	TCP_OPTIONS ,
	UDP_DATAGRAM_LENGTH,
	TYPE ,
	CODE ,
	
	BASE_HTTP_DEFS      , //the number of first definition for HTTP
	HTTP_VERSION        ,
	METHOD              ,
	URI                 ,
	USER_AGENT          ,
	ACCEPT              ,
	ACCEPT_CHARSET      ,
	ACCEPT_ENCODING     ,
	ACCEPT_LANGUAGE     ,
	ACCEPT_RANGES       ,
	AGE                 ,
	ALLOW               ,
	AUTHORIZATION       ,
	CACHE_CONTROL      	, 
	CONNECTION_TYPE     ,  
	CONTENT_TYPE        ,
	CONTENT_LENGTH      ,
	CONTENT_LOCATION    ,
	CONTENT_MD5         ,
	CONTENT_RANGE       ,
	COOKIE              ,
	ETAG                ,
	EXPECT              , 
	EXPIRES             ,
	FROM                ,
	HOST                ,
	IF_MATCH            ,
	IF_MODIFIED_SINCE   ,
	IF_NONE_MATCH       ,
	IF_RANGE            ,
	IF_UNMODIFIED_SINCE ,
	LAST_MODIFIED       ,
	MAX_FORWRDS         ,
	PRAGMA              ,
	PROXY_AUTHENTICATE  ,
	PROXY_AUTHORIZATION ,
	RANGE               ,
	REFERRER            ,
	RETRY_AFTER         ,
	SET_COOKIE          ,
	SERVER              ,
	TE                  ,
	TRAILER             ,
	TRANSFER_ENCODING   ,
	UPGRADE             ,
	VIA                 ,
	WARNING             ,
	WWW_AUTHENTICATE    ,
	X_POWERED_BY        ,
	RESPONSE_CODE       ,
	RESP_CODE_DESCR     ,
	VARY                ,
	DATE                ,
	CONTENT_ENCODING    ,
	KEEP_ALIVE          ,
	LOCATION		    ,
	CONTENT_LANGUAGE    ,
	DERIVED_FROM        ,
	ALLOWED             ,
	MIME_VERSION        ,
	TITLE               ,
	REFRESH             ,

	HTTP_PAYLOAD		, //for internal use
	END_HTTP_DEFS       ,

	//FTP FIELDS 
	BASE_FTP_DEFS ,
	//XXX me must include responses
	//all responses have a code and an argument
	USER     , //has arg
	PASS     , //has arg
	ACCT     , //has arg
	FTP_TYPE , //has arg
	STRU     ,
	MODE     ,
	CWD      , //has arg
	PWD      , //no arg
	CDUP     , //no arg
	PASV     , //no arg
	RETR     , //has arg
	REST     ,
	PORT     ,
	LIST     , //no arg
	NLST     , //yes/no arg 
	QUIT     , //no arg
	SYST     , //no arg
	STAT     , 
	HELP     ,
	NOOP     ,
	STOR     ,
	APPE     ,
	STOU     ,
	ALLO     ,
	MKD      , //has arg
	RMD      , //has arg
	DELE     , //has arg 
	RNFR     ,
	RNTO     ,
	SITE     , //has arg    
	FTP_RESPONSE_CODE,
	FTP_RESPONSE_ARG,
	END_FTP_DEFS,
	END_FIELD_DEFS,

	GAUSSIAN,
	UNIFORM,

	FLOW /* IPv6 header field, should not be here, but may break compatibility
	      * if not at the end */
} anonymizationDefs;

#define MAX_PIPELINE 50

struct httpheader {
	int http_type;
	unsigned char *pointers_to_value[MAX_PIPELINE][END_HTTP_DEFS-BASE_HTTP_DEFS+1];
	unsigned char *pointers_to_header[MAX_PIPELINE][END_HTTP_DEFS-BASE_HTTP_DEFS+1];
	unsigned int value_length[MAX_PIPELINE][END_HTTP_DEFS-BASE_HTTP_DEFS+1];
	unsigned int header_length[MAX_PIPELINE][END_HTTP_DEFS-BASE_HTTP_DEFS+1];
	int pipeline_depth;
};

struct ftpheader {
	int ftp_type;
	unsigned char *pointers_to_value[END_FTP_DEFS-BASE_FTP_DEFS+1];
	unsigned char *pointers_to_header[END_FTP_DEFS-BASE_FTP_DEFS+1];
	unsigned short value_length[END_FTP_DEFS-BASE_FTP_DEFS+1];
	unsigned short header_length[END_FTP_DEFS-BASE_FTP_DEFS+1];
};


/* for mapping functions */

typedef struct _mapValue {
    unsigned int val[4];
    unsigned char len; /* len == 1 || len == 4 */
} mapValue;

typedef struct _mapNode {
	mapValue value;
	unsigned int mapped_value;
	struct _mapNode *next;
} mapNode;

#define MAPPING_ENTRIES 1024 

/* ANONYMIZATION PROTOTYPES */
int decode_packet(int datalink,int snaplen,struct pcap_pkthdr *pkthdr,unsigned char *p,mapipacket *pkt);
int http_decode(mapipacket *p, struct httpheader *h);
int ftp_decode(mapipacket *p, struct ftpheader *h);


typedef void (*grinder_t)(mapipacket *, struct pcap_pkthdr *, u_char *,int snaplen); 

extern void PrintIPPkt(FILE * fp, int type, mapipacket * p);
extern unsigned short calculate_ip_sum(mapipacket *p);
extern unsigned short calculate_tcp_sum(mapipacket *p);
extern unsigned short calculate_udp_sum(mapipacket *p);
extern unsigned short calculate_icmp_sum(mapipacket *p);

extern void PrintPacket(FILE *fp, mapipacket *p,int datalink); 
extern void gen_table();

extern void pattern_fill_field(unsigned char *field, int len, int pattern_type, void *pattern);
extern void prefix_preserving_anonymize_field(unsigned char *raw_addr, int len);
extern void random_field(unsigned char *field, int len);
extern void filename_random_field(unsigned char *p, int len);
extern void map_distribution(unsigned char *field, short len, int distribution_type, int arg1, int arg2);
extern int aes_hash(unsigned char *field, int len, unsigned char *key, int padding_behavior, mapipacket *p);
extern int des_hash(unsigned char *field, int len, unsigned char *key, int padding_behavior, mapipacket *p);
extern void map_field(unsigned char *field, short len, mapNode **map_table,int *count);
extern int replace_field(unsigned char *field,  int len, unsigned char * pattern, int pattern_len,mapipacket *p, int total_len, unsigned char *packet_end);
extern int md5_hash(unsigned char *field, int len, int padding_behavior, mapipacket *p, int total_len, unsigned char * packet_end,int donotreplace);

extern void strip (mapipacket *p, unsigned char *field, int len,int keep_bytes, int total_len, unsigned char* packet_end);
extern int sha1_hash(unsigned char *field, int len, int padding_behavior, mapipacket *p, int total_len, unsigned char * packet_end,int donotreplace);
extern int sha256_hash(unsigned char *field, int len, int padding_behavior, mapipacket *p, int total_len, unsigned char * packet_end,int donotreplace);
extern int crc32_hash(unsigned char *field, int len, int padding_behavior, mapipacket *p, int total_len, unsigned char * packet_end,int donotreplace);

#endif
