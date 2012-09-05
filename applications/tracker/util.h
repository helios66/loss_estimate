#ifndef _UTIL_H
	#define _UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "mapi.h"

// usefull vars

int offline;
char *readfile;
int tofile;
char *writefile;
char *DEVICE;

typedef struct _count_results
{
	int fd;
	int pkt_counter;
	int byte_counter;
	int bytes;
	int pkts;
	int filter;
	int filterc;
	int open;

	pthread_mutex_t lock;
	char *filt;
	struct _count_results *next;
}count_results;

// Ethernet Protocols tracking structs
count_results ip;
count_results ip6;
count_results arp;
count_results rarp;
count_results atalk;
count_results aarp;
count_results decnet;
count_results iso;
count_results stp;
count_results ipx;
count_results sca;
count_results lat;
count_results mopdl;
count_results moprc;
count_results netbeui;

// Internet Protocols tracking structs
count_results tcp;
count_results udp;
count_results icmp;
count_results igmp;
count_results igrp;
count_results pim;
count_results ah;
count_results esp;
count_results vrrp;
count_results eigrp;

// Internet Application tracking structs
count_results kazaa;
count_results ftp;
count_results nap;
count_results mail;
count_results http;
count_results dns;
count_results msn;
count_results rtsp;
count_results netbios;
count_results ipp;
count_results hsrp;
count_results realaudio;
count_results torent;
count_results shells;
count_results gprs;
count_results kerberos;
count_results sunrpc;
count_results ssdp;
count_results ucp;
count_results who;
count_results xdmcp;

char *get_tcp_payload(struct mapipkt *pkt, int *size);
char *segment_as_string(unsigned char *segment,short size,char delim_start,char delim_end);

count_results *count_results_init(void);
void count_results_append(count_results **head, count_results *add);

// Ethernet Protocol tracking functions
void track_ip(void);
void track_ip6(void);
void track_arp(void);
void track_rarp(void);
void track_atalk(void);
void track_aarp(void);
void track_decnet(void);
void track_iso(void);
void track_stp(void);
void track_ipx(void);
void track_sca(void);
void track_lat(void);
void track_mopdl(void);
void track_moprc(void);
void track_netbeui(void);

// Internet Protocol tracking functions
void track_tcp(void);
void track_udp(void);
void track_icmp(void);
void track_igmp(void);
void track_igrp(void);
void track_pim(void);
void track_ah(void);
void track_esp(void);
void track_vrrp(void);
void track_eigrp(void);

// Internet Application tracking functions
void track_kazza(int []);
int *kaz_flag;
pthread_mutex_t *kaz_mutex;
int *kaz_pkts;
int *kaz_bytes;

void track_ftp(int []);
int *ftp_flag;
pthread_mutex_t *ftp_mutex;

void track_realaudio(int []);
int *realaudio_flag;
pthread_mutex_t *realaudio_mutex;

void track_torent(void);
void track_nap(void);
void track_mail(void);
void track_http(void);
void track_dns(void);
void track_msn(void);
void track_netbios(void);
void track_shells(void);
void track_ipp(void);
void track_hsrp(void);
void track_gprs(void);
void track_kerberos(void);
void track_sunrpc(void);
void track_ssdp(void);
void track_ucp(void);
void track_who(void);
void track_xdmcp(void);

#endif
