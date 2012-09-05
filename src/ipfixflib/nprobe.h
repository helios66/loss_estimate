/*
 *  Copyright (C) 2002-03 Luca Deri <deri@ntop.org>
 *
 *  			  http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef WIN32
#include "config.h"
#endif

#if defined(linux) || defined(__linux__)
/*
 * This allows to hide the (minimal) differences between linux and BSD
 */
#include <features.h> /* features.h undefs __FAVOR_BSD, included from tcp.h */
#define __FAVOR_BSD
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif /* linux || __linux__ */

#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#ifndef WIN32
#include <strings.h>
#endif
#include <limits.h>
#include <float.h>
#include <math.h>
#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <sys/ioctl.h>

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#ifdef HAVE_SYS_ETHERNET_H
#include <sys/ethernet.h>
#endif

#include <arpa/inet.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

/* Courtesy of Curt Sampson  <cjs@cynic.net> */
#ifdef __NetBSD__
#include <net/if_ether.h>
#endif

#include <netinet/in_systm.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#endif

#ifndef EMBEDDED
#include <sys/stat.h>
#endif

#include "md5.h"
#include "nprobe_bucket.h"
#include "npctxt.h"
#include "engine.h"

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#ifndef WIN32
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#else /* WIN32 */
#define pthread_t              HANDLE
#define pthread_mutex_t        HANDLE

/*
 * Ethernet address - 6 octets
 */
struct ether_addr {
  u_char ether_addr_octet[6];
};

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct	ether_header {
  u_char	ether_dhost[6];
  u_char	ether_shost[6];
  u_short	ether_type;
};

#if !defined (__GNUC__)
typedef	u_int	tcp_seq;
#endif

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char	th_x2:4,		/* (unused) */
		th_off:4;		/* data offset */
#else
	u_char	th_off:4,		/* data offset */
		th_x2:4;		/* (unused) */
#endif
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

/* ********************************************* */

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#else
	u_char	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	short	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/* ********************************************* */

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};

#endif /* WIN32 */

/*
  Courtesy of http://ettercap.sourceforge.net/
*/
#ifndef CFG_LITTLE_ENDIAN
#define ptohs(x) ( (u_int16_t)                       \
                      ((u_int16_t)*((u_int8_t *)x+1)<<8|  \
                      (u_int16_t)*((u_int8_t *)x+0)<<0)   \
                    )

#define ptohl(x) ( (u_int32)*((u_int8_t *)x+3)<<24|  \
                      (u_int32)*((u_int8_t *)x+2)<<16|  \
                      (u_int32)*((u_int8_t *)x+1)<<8|   \
                      (u_int32)*((u_int8_t *)x+0)<<0    \
                    )
#else
#define ptohs(x) *(u_int16_t *)(x)
#define ptohl(x) *(u_int32 *)(x)
#endif

#define TCPOPT_EOL              0
#define TCPOPT_NOP              1
#define TCPOPT_MAXSEG           2
#define TCPOPT_WSCALE           3
#define TCPOPT_SACKOK           4
#define TCPOPT_TIMESTAMP        8

/* ************************************ */

/*
 * fallbacks for essential typedefs
 */
#if !defined(HAVE_U_INT64_T)
#if defined(WIN32) && defined(__GNUC__)
typedef unsigned long long u_int64_t; /* on mingw unsigned long is 32 bits */
#else
#if defined(WIN32)
typedef _int64 u_int64_t;
#else
#if defined(HAVE_UINT64_T)
#define u_int64_t uint64_t
#else
#error "Sorry, I'm unable to define u_int64_t on your platform"
#endif
#endif
#endif
#endif

#if !defined(HAVE_U_INT32_T)
typedef unsigned int u_int32_t;
#endif

#if !defined(HAVE_U_INT16_T)
typedef unsigned short u_int16_t;
#endif

#if !defined(HAVE_U_INT8_T)
typedef unsigned char u_int8_t;
#endif

#if !defined(HAVE_INT32_T)
typedef int int32_t;
#endif

#if !defined(HAVE_INT16_T)
typedef short int16_t;
#endif

#if !defined(HAVE_INT8_T)
typedef char int8_t;
#endif

/* ************************************ */

#ifndef ETHERTYPE_IP
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#endif

#ifndef ETHERTYPE_IPV6
#define	ETHERTYPE_IPV6		0x86DD	/* IPv6 protocol */
#endif

#define NULL_HDRLEN             4

/* VLAN support - Courtesy of  Mikael Cam <mca@mgn.net> - 2002/08/28 */
#ifndef ETHER_ADDR_LEN
#define	ETHER_ADDR_LEN	6
#endif

struct	ether_vlan_header {
  u_char    evl_dhost[ETHER_ADDR_LEN];
  u_char    evl_shost[ETHER_ADDR_LEN];
  u_int16_t evl_encap_proto;
  u_int16_t evl_tag;
  u_int16_t evl_proto;
};

#ifndef ETHERTYPE_VLAN
#define	ETHERTYPE_VLAN		0x08100
#endif

#ifndef ETHERTYPE_LEN_MAX
#define ETHERTYPE_LEN_MAX  0x05DC     /* 0000-05DCIEEE802.3 Length Field */
#endif
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP      0x0806     /* Address Resolution Protocol */
#endif
#ifndef ETHERTYPE_OSX_LOOPBACK_1
#define ETHERTYPE_OSX_LOOPBACK_1 0x4001 /* Mac OSX Loopback */
#endif
#ifndef ETHERTYPE_OSX_LOOPBACK_6
#define ETHERTYPE_OSX_LOOPBACK_6 0x4006 /* Mac OSX Loopback */
#endif
#ifndef ETHERTYPE_DEC_MOP        
#define ETHERTYPE_DEC_MOP  0x6002     /* DEC MOP Remote Console*/
#endif
#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK 0x9000     /* Loopback */
#endif

/* ************************************ */



extern int createCondvar(ConditionalVariable *condvarId);
extern void deleteCondvar(ConditionalVariable *condvarId);
extern int waitCondvar(ConditionalVariable *condvarId);
extern int signalCondvar(ConditionalVariable *condvarId);

#define BUF_SIZE 512

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__

/* ************************************************ */

extern char *optarg;

/* ************************************************ */

/* ********** ICMP ******************** */
/*
 * Definition of ICMP types and code field values.
 */
#define	NPROBE_ICMP_ECHOREPLY		0		/* echo reply */
#define	NPROBE_ICMP_UNREACH		3		/* dest unreachable, codes: */
#define		NPROBE_ICMP_UNREACH_NET	0		/* bad net */
#define		NPROBE_ICMP_UNREACH_HOST	1		/* bad host */
#define		NPROBE_ICMP_UNREACH_PROTOCOL	2		/* bad protocol */
#define		NPROBE_ICMP_UNREACH_PORT	3		/* bad port */
#define		NPROBE_ICMP_UNREACH_NEEDFRAG	4		/* IP_DF caused drop */
#define		NPROBE_ICMP_UNREACH_SRCFAIL	5		/* src route failed */
#define		NPROBE_ICMP_UNREACH_NET_UNKNOWN 6		/* unknown net */
#define		NPROBE_ICMP_UNREACH_HOST_UNKNOWN 7		/* unknown host */
#define		NPROBE_ICMP_UNREACH_ISOLATED	8		/* src host isolated */
#define		NPROBE_ICMP_UNREACH_NET_PROHIB	9		/* prohibited access */
#define		NPROBE_ICMP_UNREACH_HOST_PROHIB 10		/* ditto */
#define		NPROBE_ICMP_UNREACH_TOSNET	11		/* bad tos for net */
#define		NPROBE_ICMP_UNREACH_TOSHOST	12		/* bad tos for host */
#define		NPROBE_ICMP_UNREACH_FILTER_PROHIB 13		/* admin prohib */
#define		NPROBE_ICMP_UNREACH_HOST_PRECEDENCE 14		/* host prec vio. */
#define		NPROBE_ICMP_UNREACH_PRECEDENCE_CUTOFF 15	/* prec cutoff */
#define	NPROBE_ICMP_SOURCEQUENCH	4		/* packet lost, slow down */
#define	NPROBE_ICMP_REDIRECT		5		/* shorter route, codes: */
#define		NPROBE_ICMP_REDIRECT_NET	0		/* for network */
#define		NPROBE_ICMP_REDIRECT_HOST	1		/* for host */
#define		NPROBE_ICMP_REDIRECT_TOSNET	2		/* for tos and net */
#define		NPROBE_ICMP_REDIRECT_TOSHOST	3		/* for tos and host */
#define	NPROBE_ICMP_ECHO		8		/* echo service */
#define	NPROBE_ICMP_ROUTERADVERT	9		/* router advertisement */
#define	NPROBE_ICMP_ROUTERSOLICIT	10		/* router solicitation */
#define	NPROBE_ICMP_TIMXCEED		11		/* time exceeded, code: */
#define		NPROBE_ICMP_TIMXCEED_INTRANS	0		/* ttl==0 in transit */
#define		NPROBE_ICMP_TIMXCEED_REASS	1		/* ttl==0 in reass */
#define	NPROBE_ICMP_PARAMPROB		12		/* ip header bad */
#define		NPROBE_ICMP_PARAMPROB_ERRATPTR 0		/* error at param ptr */
#define		NPROBE_ICMP_PARAMPROB_OPTABSENT 1		/* req. opt. absent */
#define		NPROBE_ICMP_PARAMPROB_LENGTH 2			/* bad length */
#define	NPROBE_ICMP_TSTAMP		13		/* timestamp request */
#define	NPROBE_ICMP_TSTAMPREPLY	14		/* timestamp reply */
#define	NPROBE_ICMP_IREQ		15		/* information request */
#define	NPROBE_ICMP_IREQREPLY		16		/* information reply */
#define	NPROBE_ICMP_MASKREQ		17		/* address mask request */
#define	NPROBE_ICMP_MASKREPLY		18		/* address mask reply */

#define	NPROBE_ICMP_MAXTYPE		18

#define abs(x) ((x) >= 0 ? (x) : -(x))

#define RTP_IANA_MAX_ASSIGNED_PT 34
#define RTP_IANA_MIN_DYNAMIC_PT  96
#define RTP_IANA_MAX_DYNAMIC_PT 127
#define RTCP_SENDER_REPORT      200
#define RTCP_RECEIVER_REPORT    201
#define RTCP_SOURCE_DESCRIPTION 202
#define RTCP_GOODBYE            203
#define RTCP_APP_DEFINED        204

struct _rtp_packet {
#if BYTE_ORDER == LITTLE_ENDIAN
  unsigned int cc:4;
  unsigned int x:1;
  unsigned int p:1;
  unsigned int v:2;
#else
  unsigned int v:2;          /* RTP version (2) */
  unsigned int p:1;          /* Padding. Is 1 if the packet is appended by padding.*/
  unsigned int x:1;          /* If extensions headers are enabled */
  unsigned int cc:4;         /* Number of contributing sources ids. */
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
  unsigned int pt:7;
  unsigned int m:1;            
#else
  unsigned int m:1;            /* Marker (frame boundary, etc.) */
  unsigned int pt:7;           /* Packet type. */
#endif

  u_int16_t seqnum;       /* Packet sequence number */
  u_int32_t ts;           /* Time stamp of the first octet in the payload */
  u_int32_t ssrc;         /* Synchronization source identifier */
};

struct _rtcp_packet {
#if BYTE_ORDER == LITTLE_ENDIAN
  unsigned int rc:5;
  unsigned int p:1;
  unsigned int v:2;
#else
  unsigned int v:2;          /* RTP version (2) */
  unsigned int p:1;          /* Padding. Is 1 if the packet is appended by padding.*/
  unsigned int rc:5;         /* Number of 'rb' (reception blocks). Can be 0. */
#endif
  u_int8_t  pt;           /* Packet type. */
  u_int16_t len;          /* Length of the RTCP packet in 32-bit words, minus one */
  u_int32_t ssrc;         /* Synchronization source identifier */
};

/* RTCP Sender info, immediately follows _rtcp_packet when sender report */
struct _rtcp_si {
  u_int32_t ts_msw;       /* NTP timestamp */
  u_int32_t ts_lsw;       /* NTP timestamp */
  u_int32_t ts_rtp;       /* RTP timestamp */
  u_int32_t pkts_sender;  /* */
  u_int32_t octets_sender;/* */
};

/* report blocks */
struct _rtcp_rb {
  u_int32_t ssrc;       /* Source identifier */
  u_int8_t  lost_fract;  /* Lost packets / expected packets * 256) */
  u_int32_t lost_pkts:24;/* Packet loss since start of reception */
  u_int32_t max_seq;    /* 0-15 is highest seq num, 16-31 are num cycles */
  u_int32_t jitter;     /* Statistical variance of interarrival time (ts) */
  u_int32_t last_sr;    /* Last SR TS */
  u_int32_t delay_sr;   /* Delay since last SR message. Units of 1/65536sec */
};

/* PIM register message header. PIM register messages are used to send
   messages from a multicast data source to another multicast group.
*/

struct _pim_register {
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int8_t  pim_type    :  4; /* PIM type, 1 for register */
  u_int8_t  pim_version :  4; /* PIM version, set to 2. */
#else
  u_int8_t  pim_version :  4; /* PIM version, set to 2. */
  u_int8_t  pim_type    :  4; /* PIM type, 1 for register */
#endif
  u_int8_t  reserved1;
  u_int16_t checksum;
  
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int32_t reserved2   : 30;
  u_int8_t  N           :  1; /* Null register bit */
  u_int8_t  B           :  1; /* Border bit */
#else
  u_int8_t  B           :  1; /* Border bit */
  u_int8_t  N           :  1; /* Null register bit */
  u_int32_t reserved2   : 30;
#endif

  /* Multicast data packet may follow */
};



/* ********* NETFLOW ****************** */

#ifdef WIN32
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef _int64 u_int64_t;
#endif

/*
  For more info see:

  http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm

  ftp://ftp.net.ohio-state.edu/users/maf/cisco/
*/

/* ***************************************** */


#define NETFLOW_MAX_BUFFER_LEN 1400

/* It must stay here as it needs the definition of v9 types */
#include "util.h"

/* ************************************ */

/*

############################################################################
#                                                                          #
# The fingerprint database has the following structure:                    #
#                                                                          #
# WWWW:MSS:TTL:WS:S:N:D:T:F:LEN:OS                                         #
#                                                                          #
# WWWW: 4 digit hex field indicating the TCP Window Size                   #
# MSS : 4 digit hex field indicating the TCP Option Maximum Segment Size   #
#       if omitted in the packet or unknown it is "_MSS"                   #
# TTL : 2 digit hex field indicating the IP Time To Live                   #
# WS  : 2 digit hex field indicating the TCP Option Window Scale           #
#       if omitted in the packet or unknown it is "WS"                     #
# S   : 1 digit field indicating if the TCP Option SACK permitted is true  #
# N   : 1 digit field indicating if the TCP Options contain a NOP          #
# D   : 1 digit field indicating if the IP Don't Fragment flag is set      #
# T   : 1 digit field indicating if the TCP Timestamp is present           #
# F   : 1 digit ascii field indicating the flag of the packet              #
#       S = SYN                                                            #
#       A = SYN + ACK                                                      #
# LEN : 2 digit hex field indicating the length of the packet              #
#       if irrilevant or unknown it is "LT"                                #
# OS  : an ascii string representing the OS                                #
#                                                                          #
# IF YOU FIND A NEW FINGERPRING, PLEASE MAIL IT US WITH THE RESPECTIVE OS  #
# or use the appropriate form at:                                          #
#    http://ettercap.sourceforge.net/index.php?s=stuff&p=fingerprint       #
#                                                                          #
# TO GET THE LATEST DATABASE:                                              #
#                                                                          #
#    http://cvs.sourceforge.net/cgi-bin/viewcvs.cgi/~checkout~/ettercap/   #
#           ettercap/etter.passive.os.fp?rev=HEAD&content-type=text/plain  #
#                                                                          #
############################################################################
*/


/*
struct in6_addr
{
  union
  {
    u_int8_t u6_addr8[16];
    u_int16_t u6_addr16[8];
    u_int32_t u6_addr32[4];
  } in6_u;
};
*/


/* ************************************ */

struct mypcap {
  int fd, snapshot, linktype, tzoff, offset;
  FILE *rfile;

  /* Other fields have been skipped. Please refer
     to pcap-int.h for the full datatype.
  */
};

/* ************************************ */

#define DEFAULT_SNAPLEN 128
#define DUMP_TIMEOUT    30 /* seconds */

/* #define DEBUG  */


#define HASH_SIZE       4096 * 16 /* Buckets. This allocates abt 75 MB. */

#ifndef WIN32
#define USE_SYSLOG 1
#else
#undef USE_SYSLOG
#endif

extern int getopt(int num, char *const *argv, const char *opts);
extern char *optarg;

/* *************************** */

extern u_int bucketsLeft;
extern u_int bucketsAdded, bucketsFreed;
extern u_short maxPayloadLen;
extern int traceLevel;
#ifndef WIN32
extern int useSyslog;
#endif
extern u_char ignoreAS;

/* version.c */
extern char *version, *osName, *buildDate;


/* *************************** */

#define MAX_DEMO_FLOWS    1000
#ifdef DEMO
#define DEMO_MODE
#endif

#define DEFAULT_OBSERVATION_DOMAIN 0
