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

#ifdef __KERNEL__
#include "sniffer_mod.h"
#include "nprobe_mod.h"
#include "mod_typedefs.h"
#include "engine.h"
#else /* __KERNEL__ */
#include "nprobe.h"
#endif /* __KERNEL__ */

/* ******************************************* */

#define FID_HISTOGRAM_PKT_LNGTH 32769
#define FID_HISTOGRAM_PKT_DIST  32770
#define FID_PAYLOAD             32776
#define FID_VAR_PKT_DIST        32790
#define FID_EXPVAL_PKT_DIST     32791
#define FID_VAR_PKT_LENGTH      32792
#define FID_EXPVAL_PKT_LENGTH   32793
#define FID_SUM_PKT_DIST        32794
#define FID_SUM_PKT_LENGTH      32795
#define FID_QSUM_PKT_DIST       32796
#define FID_QSUM_PKT_LENGTH     32797
#define FID_CONNDIRECTION       32798
#define FID_PACKET_REORDER      32799
#define FID_SERVICE_TYPE        32800

/* In RTP time units. Never worked. */
#define FID_RTCP_JITTER         32801
#define FID_RTCP_LOSTFRACTION   32802
#define FID_RTCP_LOSTPKTS       32803
#define FID_RTCP_SEQCYCLES      32804

#define FID_PIM_COUNT           32805

/* In microseconds. */
#define FID_RTP_JITTER_MEAN     32806
#define FID_RTP_JITTER_STDV     32807
/* If we leave out min, somebody is going to ask why. In practice, it's
 * always going to be close to 0 */
#define FID_RTP_JITTER_MIN      32808
#define FID_RTP_JITTER_MAX      32809

#define FID_RATE_1SEC_MAX       33000
#define FID_RATE_1SEC_MIN       33001
#define FID_RATE_100MS_MAX      33002
#define FID_RATE_100MS_MIN      33003
#define FID_RATE_10MS_MAX       33004
#define FID_RATE_10MS_MIN       33005
#define FID_RATE_1MS_MAX        33006
#define FID_RATE_1MS_MIN        33007

#define FID_TCPWIN_MAX          33008
#define FID_TCPWIN_MIN          33009
#define FID_TCPWIN_EFF          33010

#define FID_MPEGTS_DISCONTINUITY_COUNT 33011
#define FID_MPEGTS_TOTAL_COUNT 33012
#define FID_MPEGTS_JITTER_MEAN	33013
#define FID_MPEGTS_JITTER_STDV	33014
#define FID_UNUSED_1 33015
#define FID_UNUSED_2 33016
/* FIDs for UNINETT enterprise specific fields over NetFlow V9 transport - Q9 for 'quasi 9' */

#define FID_Q9_HISTOGRAM_PKT_LNGTH 220
#define FID_Q9_HISTOGRAM_PKT_DIST  221
#define FID_Q9_PAYLOAD             222
#define FID_Q9_VAR_PKT_DIST        223
#define FID_Q9_EXPVAL_PKT_DIST     224
#define FID_Q9_VAR_PKT_LENGTH      225
#define FID_Q9_EXPVAL_PKT_LENGTH   226
#define FID_Q9_SUM_PKT_DIST        227
#define FID_Q9_SUM_PKT_LENGTH      228
#define FID_Q9_QSUM_PKT_DIST       229
#define FID_Q9_QSUM_PKT_LENGTH     230
#define FID_Q9_CONNDIRECTION       231
#define FID_Q9_PACKET_REORDER      232
#define FID_Q9_SERVICE_TYPE        233

#define FID_Q9_RTP_JITTER_MEAN     234
#define FID_Q9_RTP_JITTER_STDV     235
/* If we leave out min, somebody is going to ask why. In practice, it's
 * always going to be close to 0 */
#define FID_Q9_RTP_JITTER_MIN      236
#define FID_Q9_RTP_JITTER_MAX      237

#define FID_Q9_PIM_COUNT           238

#define FID_Q9_RATE_1SEC_MAX       239
#define FID_Q9_RATE_1SEC_MIN       240
#define FID_Q9_RATE_100MS_MAX      241
#define FID_Q9_RATE_100MS_MIN      242
#define FID_Q9_RATE_10MS_MAX       243
#define FID_Q9_RATE_10MS_MIN       244
#define FID_Q9_RATE_1MS_MAX        245
#define FID_Q9_RATE_1MS_MIN        246

#define FID_Q9_TCPWIN_MAX          247
#define FID_Q9_TCPWIN_MIN          248
#define FID_Q9_TCPWIN_EFF          249

#define FID_Q9_MPEGTS_DISCONTINUITY_COUNT 250
#define FID_Q9_MPEGTS_TOTAL_COUNT 251
#define FID_Q9_MPEGTS_JITTER_MEAN 252
#define FID_Q9_MPEGTS_JITTER_STDV 253
#define FID_Q9_UNUSED_1 	  254
#define FID_Q9_UNUSED_2 	  255

#ifndef WIN32
static u_char syslog_opened = 0;
static char *nprobeId = "ipfixlib";
#endif

#ifndef __KERNEL__

static FILE*
openLogfile(void)
{
  char tmstr[100];
  char strbuf[256];
  struct tm loctime;
  time_t now = time(NULL);
  FILE *loghandle;
   
  (void) localtime_r(&now, &loctime);

  strftime(tmstr, sizeof tmstr, "%Y-%m-%dT%H:%M", &loctime);
  snprintf(strbuf, sizeof strbuf, "/var/log/ipfixlib-%s.log", tmstr);
  loghandle = fopen(strbuf, "w");
  if (!loghandle) {
    snprintf(strbuf, sizeof strbuf, "/tmp/ipfixlib-%s.log", tmstr);
    loghandle = fopen(strbuf, "w");
  }
  return loghandle;
}

void traceEvent(np_ctxt_t *npctxt, int eventTraceLevel, char* file, int line, char * format, ...) {
  va_list va_ap;

  if(eventTraceLevel <= traceLevel) {
    char buf[2048], out_buf[640];
    char theDate[32], *extra_msg = "";
    time_t theTime = time(NULL);
    int instanceNo = npctxt ? npctxt->instanceNo : -1;

    va_start (va_ap, format);

    /* We have two paths - one if we're logging, one if we aren't
     *   Note that the no-log case is those systems which don't support it (WIN32),
     *                                those without the headers !defined(USE_SYSLOG)
     *                                those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */)
      extra_msg = "ERROR: ";
    else if(eventTraceLevel == 1 /* TRACE_WARNING */)
      extra_msg = "WARNING: ";

    while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

    snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] <%d> %s%s", theDate, file, line, instanceNo, extra_msg, buf);

#ifndef WIN32
    if(useSyslog) {
      if(!syslog_opened) {
	openlog(nprobeId, LOG_PID, LOG_DAEMON);
	syslog_opened = 1;
      }

      syslog(LOG_INFO, out_buf);
    } else if (npctxt->traceToFile) {
      if(!npctxt->logfileOpened) {
	npctxt->loghandle = openLogfile();
	npctxt->logfileOpened = 1;
      }
      if (npctxt->loghandle) {
	fprintf(npctxt->loghandle, "%s\n", out_buf);
	fflush(npctxt->loghandle);
      }
    } else
      printf("%s\n", out_buf);
#else
    printf("%s\n", out_buf);
#endif
  }

  fflush(stdout);
  va_end(va_ap);
}

/* ************************************ */

#undef sleep

int nprobe_sleep(int secs) {
  int unsleptTime = secs;

  while((unsleptTime = sleep(unsleptTime)) > 0)
    ;

  return(secs);
}

#endif /* __KERNEL__ */

/* ************************************ */

#ifdef WIN32
unsigned long waitForNextEvent(unsigned long ulDelay /* ms */) {
  unsigned long ulSlice = 1000L; /* 1 Second */

  while(ulDelay > 0L) {
    if(ulDelay < ulSlice)
      ulSlice = ulDelay;
    Sleep(ulSlice);
    ulDelay -= ulSlice;
  }

  return ulDelay;
}

/* ******************************* */

void initWinsock32() {
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  wVersionRequested = MAKEWORD(2, 0);
  err = WSAStartup( wVersionRequested, &wsaData );
  if( err != 0 ) {
    /* Tell the user that we could not find a usable */
    /* WinSock DLL.                                  */
    traceEvent(npctxt, TRACE_ERROR, "FATAL ERROR: unable to initialise Winsock 2.x.");
    exit(-1);
  }
}

/* ******************************** */

short isWinNT() {
  DWORD dwVersion;
  DWORD dwWindowsMajorVersion;

  dwVersion=GetVersion();
  dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
  if(!(dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4))
    return 1;
  else
    return 0;
}

/* ****************************************************** */

int snprintf(char *string, size_t maxlen, const char *format, ...) {
  int ret=0;
  va_list args;

  va_start(args, format);
  vsprintf(string,format,args);
  va_end(args);
  return ret;
}

#endif /* Win32 */

/* ****************************************************** */

#ifndef __KERNEL__

void checkHostFingerprint(char *fingerprint, char *osNameBuf, int osNameLen) {
  FILE *fd = NULL;
  char *WIN, *MSS, *WSS, *ttl, *flags;
  int S, N, D, T, done = 0;
  char *strtokState;

  osNameBuf[0] = '\0';
  strtokState = NULL;
  WIN = strtok_r(fingerprint, ":", &strtokState);
  MSS = strtok_r(NULL, ":", &strtokState);
  ttl = strtok_r(NULL, ":", &strtokState);
  WSS = strtok_r(NULL, ":", &strtokState);
  S = atoi(strtok_r(NULL, ":", &strtokState));
  N = atoi(strtok_r(NULL, ":", &strtokState));
  D = atoi(strtok_r(NULL, ":", &strtokState));
  T = atoi(strtok_r(NULL, ":", &strtokState));
  flags = strtok_r(NULL, ":", &strtokState);

  fd = fopen("etter.passive.os.fp", "r");

  if(fd) {
    char line[384];
    char *b, *d, *ptr;

    while((!done) && fgets(line, sizeof(line)-1, fd)) {
      if((line[0] == '\0') || (line[0] == '#') || (strlen(line) < 30)) continue;
      line[strlen(line)-1] = '\0';

      strtokState = NULL;
      ptr = strtok_r(line, ":", &strtokState); if(ptr == NULL) continue;
      if(strcmp(ptr, WIN)) continue;
      b = strtok_r(NULL, ":", &strtokState); if(b == NULL) continue;
      if(strcmp(MSS, "_MSS") != 0) {
	if(strcmp(b, "_MSS") != 0) {
	  if(strcmp(b, MSS)) continue;
	}
      }

      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(strcmp(ptr, ttl)) continue;

      d = strtok_r(NULL, ":", &strtokState); if(d == NULL) continue;
      if(strcmp(WSS, "WS") != 0) {
	if(strcmp(d, "WS") != 0) {
	  if(strcmp(d, WSS)) continue;
	}
      }

      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(atoi(ptr) != S) continue;
      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(atoi(ptr) != N) continue;
      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(atoi(ptr) != D) continue;
      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(atoi(ptr) != T) continue;
      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(strcmp(ptr, flags)) continue;

      /* NOTE
	 strlen(srcHost->fingerprint) is 29 as the fingerprint length is so
	 Example: 0212:_MSS:80:WS:0:1:0:0:A:LT
      */

      snprintf(osNameBuf, osNameLen, "%s", &line[29]);
      done = 1;
    }

    fclose(fd);
  }
}

/* *************************************************** */

/* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */

typedef struct IPNode {
  struct IPNode *b[2];
  u_short as;
} IPNode;

IPNode *asHead = NULL;
u_long asMem = 0, asCount=0;

/* *************************************************** */

/* Courtesy of Andreas Pfaller <apfaller@yahoo.com.au> */

static u_int32_t xaton(char *s) {
  u_int32_t a, b, c, d;

  if(4!=sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d))
    return 0;
  return((a&0xFF)<<24)|((b&0xFF)<<16)|((c&0xFF)<<8)|(d&0xFF);
}

/* ******************************************************************* */

static void addNodeInternal(u_int32_t ip, int prefix, u_short as) {
  IPNode *p1 = asHead;
  IPNode *p2 = NULL;
  int i, b;

  for(i=0; i<prefix; i++) {
    b=(ip>>(31-i)) & 0x1;
    if(!p1->b[b]) {
      if(!(p2=malloc(sizeof(IPNode))))
        exit(1);
      memset(p2, 0, sizeof(IPNode));
      asMem += sizeof(IPNode);
      p1->b[b]=p2;
    }
    else
      p2=p1->b[b];

    p1=p2;
  }

  if(p2->as == 0)
    p2->as = as;
}

/* ******************************************************************* */

u_short ip2AS(IpAddress ip) {
  if(ignoreAS || ip.ipVersion != 4)
    return(0);
  else {
    IPNode *p=asHead;
    int i, b;
    u_short as=0;

    i=0;
    while(p != NULL) {
      if(p->as !=0 )
	as = p->as;
      b = (ip.ipType.ipv4 >> (31-i)) & 0x1;
      p = p->b[b];
      i++;
    }

    return as;
  }
}

/* ************************************ */

void readASs(char *path) {
  if(ignoreAS || (path == NULL))
    return;
  else {
    FILE *fd;
    u_char useGz;

    traceEvent(NULL, TRACE_INFO, "Attempting to read AS table from file %s", path);

#ifdef HAVE_ZLIB_H
    if(!strcmp(&path[strlen(path)-3], ".gz")) {
      useGz = 1;
      fd = gzopen(path, "r");
    } else
#endif
      {
	useGz = 0;
	fd = fopen(path, "r");
      }

    if(fd != NULL) {
      asHead = malloc(sizeof(IPNode));
      memset(asHead, 0, sizeof(IPNode));
      asHead->as = 0;
      asMem += sizeof(IPNode);

      while(1) {
	char buff[256];
	char *strtokState, *as, *ip, *prefix;

#ifdef HAVE_ZLIB_H
	if(useGz) {
	  if(gzeof(fd)) break;
	} else
#endif
	  {
	    if(feof(fd)) break;
	  }

#ifdef HAVE_ZLIB_H
	if(useGz) {
	  if(gzgets(fd, buff, sizeof(buff)) == NULL) continue;
	} else
#endif
	  {
	    if(fgets(buff, sizeof(buff), fd) == NULL) continue;
	  }

	if((as = strtok_r(buff, ":", &strtokState)) == NULL)  continue;
	if((ip = strtok_r(NULL, "/", &strtokState)) == NULL)  continue;
	if((prefix = strtok_r(NULL, "\n", &strtokState)) == NULL)  continue;

	addNodeInternal(xaton(ip), atoi(prefix), atoi(as));
	asCount++;
      }

#ifdef HAVE_ZLIB_H
      if(useGz)
	gzclose(fd);
      else
#endif
	fclose(fd);

      traceEvent(NULL, TRACE_INFO, "Read %d ASs [Used %d KB of memory]", asCount, asMem/1024);
    } else
      traceEvent(NULL, TRACE_ERROR, "Unable to read file %s", path);

    if(asCount > 0)
      ignoreAS = 0;
    else
      ignoreAS = 1;
  }
}

/* ******************************************** */

void nprintf(FILE *stream, char *fmt, HashBucket *theFlow, int direction) {
  char buf[256];

  for(; *fmt; fmt++) {	/* scan format string characters */
    switch(*fmt) {
    case '%':	        /* special format follows */
      switch(*++fmt) {
      case '%':		/* print a percent character */
	putc('%', stream);
	break;
      case 'd':
	switch(*++fmt) {
	case 'a':
	  /* Destination IP Address(IPv4/6) */
	  fprintf(stream, "%s", direction == 0 ? _intoa(theFlow->dst, buf, sizeof(buf)):_intoa(theFlow->src, buf, sizeof(buf)));
	  break;
	case 'o':
	  /* Destination Octets */
	  fprintf(stream, "%lu", direction == 0 ? theFlow->bytesSent : theFlow->bytesRcvd);
	  break;
	case 'p':
	  /* Destination Packets */
	  fprintf(stream, "%lu", direction == 0 ? (unsigned long)theFlow->pktSent : (unsigned long)theFlow->pktRcvd);
	  break;
	case 'P':
	  /* Destination Port */
	  fprintf(stream, "%d", direction == 0 ? theFlow->dport : theFlow->sport);
	  break;
	case 's':
	  /* Destination AS */
	  fprintf(stream, "%d", direction == 0 ? ip2AS(theFlow->src) : ip2AS(theFlow->dst));
	  break;
	}
	break;
      case 'f':
	switch(*++fmt) {
	case 'r':
	  /* SysUptime at start of flow */
	  	  fprintf(stream, "%lu", direction == 0 ? toMs(theFlow->firstSeenSent) : toMs(theFlow->firstSeenRcvd));
	  break;
	case 'm':
	  /* Fragmented Packets */
	  fprintf(stream, "%d", direction == 0 ? fragmentedPacketSrc2Dst(theFlow) : fragmentedPacketDst2Src(theFlow));
	  break;
	case 'p':
	  /* Host Fingerprint */
	  fprintf(stream, "%s", direction == 0 ? theFlow->src2dstFingerprint : theFlow->dst2srcFingerprint);
	  break;
	}
	break;
      case 'i':
	switch(*++fmt) {
	case 'f':
	  /* ICMP Flags */
	  fprintf(stream, "%d", direction == 0 ? theFlow->src2dstIcmpFlags : theFlow->dst2srcIcmpFlags);
	  break;
/* 	case 'n': */
	  /* Input interface index */
/* 	  fprintf(stream, "%d", ingress_interface); */
/* 	  break; */
	}
	break;
      case 'l':
	switch(*++fmt) {
	case 'a':
	  /* SysUptime at end of flow */
	  fprintf(stream, "%lu", direction == 0 ? toMs(theFlow->lastSeenSent) : toMs(theFlow->lastSeenRcvd));
	  break;
	}
	break;
      case 'm':
	switch(*++fmt) {
	case 'h':
	  /* MPLS header */
	  fprintf(stream, "%d", 0); /* dummy */
	  break;
	}
	break;
      case 'n':
	switch(*++fmt) {
	case 'n':
	  /* TCP Nw Latency(nsec) */
	  fprintf(stream, "%ld", 
		  (unsigned long ) (((theFlow->nwLatency & 0xffffffff) * 1000)
				    / 4295));
	  break;
	case 's':
	  /* TCP Nw Latency(sec) */
	  fprintf(stream, "%lu", (long unsigned int)(theFlow->nwLatency >> 32));
	  break;
	}
	break;
      case 'o':
	switch(*++fmt) {
	case 'u':
	  /* Output interface index */
	  fprintf(stream, "%d", 255 /* unknown */);
	  break;
	}
	break;
      case 'p':
	switch(*++fmt) {
	case 'a':
	  /* Payload */
	  if(direction == 0) {
	    int i; for(i=0; i<theFlow->src2dstPayloadLen; i++) fprintf(stream, "%c", theFlow->src2dstPayload[i]);
	  } else {
	    int i; for(i=0; i<theFlow->dst2srcPayloadLen; i++) fprintf(stream, "%c", theFlow->dst2srcPayload[i]);
	  }
	  break;
	case 'l':
	  /* Payload Len */
	  fprintf(stream, "%d", direction == 0 ? theFlow->src2dstPayloadLen : theFlow->dst2srcPayloadLen);
	  break;
	case 'r':
	  /* IP Protocol */
	  fprintf(stream, "%d", theFlow->proto);
	  break;
	case 'n':
	  { 
	    /* Appl Latency(nsec) */
	    unsigned long long lat;

	    lat = (direction == 0) 
	      ? theFlow->src2dstApplLatency
	      : theFlow->dst2srcApplLatency;
	    fprintf(stream, "%llu", ((lat & 0xffffffff) * 1000) / 4295);
		    
	    break;
	  }
	case 's':
	  { 
	    /* Appl Latency(sec) */
	    unsigned long long lat;

	    lat = (direction == 0) 
	      ? theFlow->src2dstApplLatency
	      : theFlow->dst2srcApplLatency;
	    fprintf(stream, "%llu", (lat >> 32));
	    break;
	  }
	}
	break;
      case 'r':
	switch(*++fmt) {
	case 'o':
	  /* Destination Octets */
	  fprintf(stream, "%lu", direction == 0 ? theFlow->bytesRcvd : theFlow->bytesSent);
	  break;
	case 'p':
	  /* Destination Packets */
	  fprintf(stream, "%lu", direction == 0 ? (unsigned long)theFlow->pktRcvd : (unsigned long)theFlow->pktSent);
	  break;
	}
	break;
      case 's':
	switch(*++fmt) {
	case 'a':
	  /* Source IP Address(IPv4/6) */
	  fprintf(stream, "%s", direction == 0 ? _intoa(theFlow->src, buf, sizeof(buf)):_intoa(theFlow->dst, buf, sizeof(buf)));
	  break;
	case 'p':
	  /* Source Port */
	  fprintf(stream, "%d", direction == 0 ? theFlow->sport : theFlow->dport);
	  break;
	case 'P':
	  /* Source AS */
	  fprintf(stream, "%d", direction == 0 ? ip2AS(theFlow->dst) : ip2AS(theFlow->src));
	  break;
	}
	break;
      case 't':
	switch(*++fmt) {
	case 'f':
	  /* TCP Flags */
	  fprintf(stream, "%d", direction == 0 ? theFlow->src2dstTcpFlags : theFlow->dst2srcTcpFlags);
	  break;
	case 's':
	  /* Type of Service */
	  fprintf(stream, "%d", direction == 0 ? theFlow->src2dstTos : theFlow->dst2srcTos);
	  break;
	}
	break;
      case 'v':
	switch(*++fmt) {
	case 't':
	  /* VLAN tag */
	  fprintf(stream, "%d", 0); /* dummy */
	  break;
	}
	break;
      }
      break;
    default:
      putc(*fmt, stream);
    }
  }

  putc('\n', stream);
}


/**
 * This method does not really belong here, but where else to put
 * it...
 */
unsigned long long htonll(unsigned long long n) {
  return (((u_int64_t)(ntohl((u_int32_t)((n << 32) >> 32))) << 32) | 
	  (u_int32_t)ntohl(((u_int32_t)(n >> 32))));
  /*return (((unsigned long long)htonl(n)) << 32) + htonl(n >> 32);*/
}

/* ********* NetFlow v9/IPFIX ***************************** */

/* Don't *ever* add a field here without adding it to the
 * switch statement in handleTemplate as well. */
static V9TemplateId ver9_templates[] = {
  /* { 0,  0, "NOT_USED" }, */
  { 1,  8, "BYTES" },
  { 2,  8, "PKTS" },
  /*{ 3,  4, "FLOWS" }, */
  { 4,  1, "PROT" },
  { 5,  1, "TOS" },
  { 6,  1, "TCP_FLAGS" },
  { 7,  2, "L4_SRC_PORT" },
  { 8,  4, "IP_SRC_ADDR" },
  /*{ 9,  1, "SRC_MASK" }, */
  { 10,  2, "INGRESS" }, /* old: INPUT_SNMP */
  { 11,  2, "L4_DST_PORT" },
  { 12,  4, "IP_DST_ADDR" },
  /*{ 13,  1, "DST_MASK" }, */
  { 14,  2, "EGRESS" }, /* old: OUTPUT_SNMP */
  /*{ 15,  4, "IP_NEXT_HOP" },*/
  { 16,  2, "SRC_AS" },
  { 17,  2, "DST_AS" },
  /*{ 18,  4, "BGP_NEXT_HOP" },
  { 19,  4, "MUL_DPKTS" },
  { 20,  4, "MUL_DOCTETS" },*/
  { 21,  4, "LAST_SWITCHED" },
  { 22,  4, "FIRST_SWITCHED" },
  /*{ 23,  4, "OUT_BYTES" },
    { 24,  4, "OUT_PKTS" },*/ /* NOTE: difference v9/ipfix */
  { 25,  2, "MIN_PKT_LNGTH" }, 
  { 26,  2, "MAX_PKT_LNGTH" }, 
  { 27,  16, "IPV6_SRC_ADDR" },
  { 28,  16, "IPV6_DST_ADDR" },
  /*
  { 29,  1, "IPV6_SRC_MASK" },
  { 30,  1, "IPV6_DST_MASK" },
  { 31,  3, "FLOW_LABEL_IPV6" },
  { 32,  2, "ICMP_TYPE" },
  { 33,  1, "IGMP_TYPE" },
  { 34,  4, "SAMPLING_INTERVAL" },
  { 35,  1, "SAMPLING_ALGO" },
  */
  { 36,  2, "ACTIVE_TIMEOUT" },
  { 37,  2, "INACTIVE_TIMEOUT" },  
  { 38,  1, "ENGINE_TYPE" }, /* not ipfix */
  { 39,  1, "ENGINE_ID" }, /* not ipfix */
  { 40,  8, "BYTES_EXP" },
  { 41,  8, "PKTS_EXP" },
  { 42,  8, "FLOWS_EXP" },
  { 52,  1, "MIN_TTL" },
  { 53,  1, "MAX_TTL" },

  { 60,  1, "IP_PROTO_VER" },
  /*
  { 61,  1, "DIRECTION" },
  { 62,  16, "IPV6_NEXT_HOP" },
  { 63,  16, "BPG_IPV6_NEXT_HOP" },
  */
  { 64,  4, "IPV6_OPT_HDR" },

  /* nFlow Extensions */
  /*
  { 80,  1, "FRAGMENTED" },
  { 81,  FINGERPRINT_LEN, "FINGERPRINT" },
  { 82,  2, "VLAN_TAG" },
  { 83,  4, "NW_LATENCY_SEC" },
  { 84,  4, "NW_LATENCY_NSEC" },
  { 85,  4, "APPL_LATENCY_SEC" },
  { 86,  4, "APPL_LATENCY_NSEC" },
  */
  /*{ 88,  4, "ICMP_FLAGS" },*/

  {130,	 4, "EXPORTER_IPV4"},
  {131,	16, "EXPORTER_IPV6"},
  {136,	 1, "FLOW_END_REASON"},
  {145,	 4, "TEMPLATE_ID"},
  {148,	 4, "FLOW_ID"},
  {149,  4, "OBSERV_DOMAIN"},
  {150,  4, "FLOW_START_SEC" },
  {151,  4, "FLOW_END_SEC" },
  {152,  8, "FLOW_START_MS" },
  {153,  8, "FLOW_END_MS" },
  {154,  8, "FLOW_START_US" },
  {155,  8, "FLOW_END_US" },
  {156,  8, "FLOW_START_NS" },
  {157,  8, "FLOW_END_NS" },
  {160,	 8, "SYSINIT_MS"},
  {161,	 8, "FLOW_DUR_MS"},
  {162,	 8, "FLOW_DUR_US"},
  {163,	 8, "NUM_FLOWS_OBSERVED"},
  {164,	 8, "NUM_IGNORED_PKT"},
  {165,	 8, "NUM_IGNORED_OCTETS"},
  {166,	 8, "NOTSENT_FLOWS"},
  {167,	 8, "NOTSENT_PKTS"},
  {168,	 8, "NOTSENT_OCTETS"},
  {186,  2, "TCP_WINDOW"},
  {190,	 2, "PKTLEN_IPV4"},
  {191,	 4, "PAYLOADLEN_IPV6"},
  {207,	 1, "HDRLEN_IPV4"},
  {208,	 8, "IPV4_OPT"},
  {209,	 8, "TCP_OPT"},
  {210,  1, "PADDING"},
  
  /* ipfixlib extensions */
  /* Note that 32768 is reserved (ent.mark = 1, ent.id = 0) */
  { FID_HISTOGRAM_PKT_LNGTH, PKTSZ_HISTOGRAM_SLOTS*sizeof(u_int8_t), "HIST_PKT_LEN" },
  { FID_HISTOGRAM_PKT_DIST, PKTDIST_HISTOGRAM_SLOTS*sizeof(u_int8_t), "HIST_PKT_DIST" },
  { FID_PAYLOAD, PAYLOAD_EXCERPT_MAX, "PAYLOAD" },
  { FID_VAR_PKT_DIST,     4, "VAR_PKT_DIST" },      /* returns float-32 */
  { FID_EXPVAL_PKT_DIST,  4, "EXPVAL_PKT_DIST" },   /* returns float-32 */
  { FID_VAR_PKT_LENGTH,   4, "VAR_PKT_LENGTH" },    /* returns float-32 */
  { FID_EXPVAL_PKT_LENGTH,4, "EXPVAL_PKT_LENGTH" }, /* returns float-32 */
  { FID_SUM_PKT_DIST,     8, "SUM_PKT_DIST" },
  { FID_SUM_PKT_LENGTH,   8, "SUM_PKT_LENGTH" },
  { FID_QSUM_PKT_DIST,    8, "QSUM_PKT_DIST" },
  { FID_QSUM_PKT_LENGTH,  8, "QSUM_PKT_LENGTH" }, 
  { FID_CONNDIRECTION,    1, "CONN_DIRECTION" },
  { FID_PACKET_REORDER,   4, "PKT_REORDERED" },
  { FID_SERVICE_TYPE,     2, "SERVICE" },

  { FID_RTCP_JITTER,      4, "RTCP_JITTER" },
  { FID_RTCP_LOSTFRACTION,1, "RTCP_LOSTFRAC" },
  { FID_RTCP_LOSTPKTS,    4, "RTCP_LOSTPKTS" },
  { FID_RTCP_SEQCYCLES,   2, "RTCP_SEQCYCLES" },

  { FID_PIM_COUNT,        1, "PIM_COUNT" },

  { FID_RTP_JITTER_MEAN, 4, "RTP_JITTER_MEAN" },
  { FID_RTP_JITTER_STDV, 4, "RTP_JITTER_STDV" },
  { FID_RTP_JITTER_MIN,   4, "RTP_JITTER_MIN" },
  { FID_RTP_JITTER_MAX,   4, "RTP_JITTER_MAX" },

  /* MPEG-TS measurments */
  { FID_MPEGTS_JITTER_MEAN, 4, "MPEGTS_JITTER_MEAN" },
  { FID_MPEGTS_JITTER_STDV, 4, "MPEGTS_JITTER_STDV" },
  { FID_MPEGTS_DISCONTINUITY_COUNT, 4, "MPEGTS_DISCONTINUITY_COUNT" },
  { FID_MPEGTS_TOTAL_COUNT, 4, "MPEGTS_TOTAL_COUNT" },

  { FID_UNUSED_1, 4, "UNUSED_1" },
  { FID_UNUSED_2, 4, "UNUSED_2" },

  { FID_RATE_1SEC_MAX,  4, "MAXRATE_1SEC" },
  { FID_RATE_1SEC_MIN,  4, "MINRATE_1SEC" },
  { FID_RATE_100MS_MAX, 4, "MAXRATE_100MS" },
  { FID_RATE_100MS_MIN, 4, "MINRATE_100MS" },
  { FID_RATE_10MS_MAX,  4, "MAXRATE_10MS" },
  { FID_RATE_10MS_MIN,  4, "MINRATE_10MS" },
  { FID_RATE_1MS_MAX,   4, "MAXRATE_1MS" },
  { FID_RATE_1MS_MIN,   4, "MINRATE_1MS" },

  { FID_TCPWIN_MAX,     4, "TCPWIN_MAX" },
  { FID_TCPWIN_MIN,     4, "TCPWIN_MIN" },
  { FID_TCPWIN_EFF,     4, "TCPWIN_EFF" },

  { 0,   0, NULL }
};

/* Kluge to support the two different ways of handling UNINETT enterprise specific fields. */
void select_entspec_format(np_ctxt_t *npctxt)
{
	V9TemplateId *p;
	int is_ipfix = (npctxt->netFlowVersion == 0x0a);

	for (p = ver9_templates; p->templateId != 0; p++) {
		switch(p->templateId) {
		case FID_HISTOGRAM_PKT_LNGTH:
		case FID_Q9_HISTOGRAM_PKT_LNGTH:
			p->templateId = is_ipfix ? FID_HISTOGRAM_PKT_LNGTH : FID_Q9_HISTOGRAM_PKT_LNGTH;
			break;
		case FID_HISTOGRAM_PKT_DIST:
		case FID_Q9_HISTOGRAM_PKT_DIST:
			p->templateId = is_ipfix ? FID_HISTOGRAM_PKT_DIST : FID_Q9_HISTOGRAM_PKT_DIST;
			break;
		case FID_PAYLOAD:
		case FID_Q9_PAYLOAD:
			p->templateId = is_ipfix ? FID_PAYLOAD: FID_Q9_PAYLOAD;
			break;
		case FID_VAR_PKT_DIST:
		case FID_Q9_VAR_PKT_DIST:
			p->templateId = is_ipfix ? FID_VAR_PKT_DIST : FID_Q9_VAR_PKT_DIST;
			break;
		case FID_EXPVAL_PKT_DIST:
		case FID_Q9_EXPVAL_PKT_DIST:
			p->templateId = is_ipfix ? FID_EXPVAL_PKT_DIST : FID_Q9_EXPVAL_PKT_DIST;
			break;
		case FID_VAR_PKT_LENGTH:
		case FID_Q9_VAR_PKT_LENGTH:
			p->templateId = is_ipfix ? FID_VAR_PKT_LENGTH : FID_Q9_VAR_PKT_LENGTH;
			break;
		case FID_EXPVAL_PKT_LENGTH:
		case FID_Q9_EXPVAL_PKT_LENGTH:
			p->templateId = is_ipfix ? FID_EXPVAL_PKT_LENGTH : FID_Q9_EXPVAL_PKT_LENGTH;
			break;
		case FID_SUM_PKT_DIST:
		case FID_Q9_SUM_PKT_DIST:
			p->templateId = is_ipfix ? FID_SUM_PKT_DIST : FID_Q9_SUM_PKT_DIST;
			break;
		case FID_SUM_PKT_LENGTH:
		case FID_Q9_SUM_PKT_LENGTH:
			p->templateId = is_ipfix ? FID_SUM_PKT_LENGTH : FID_Q9_SUM_PKT_LENGTH;
			break;
		case FID_QSUM_PKT_DIST:
		case FID_Q9_QSUM_PKT_DIST:
			p->templateId = is_ipfix ? FID_QSUM_PKT_DIST : FID_Q9_QSUM_PKT_DIST;
			break;
		case FID_QSUM_PKT_LENGTH:
		case FID_Q9_QSUM_PKT_LENGTH:
			p->templateId = is_ipfix ? FID_QSUM_PKT_LENGTH : FID_Q9_QSUM_PKT_LENGTH;
			break;
		case FID_CONNDIRECTION:
		case FID_Q9_CONNDIRECTION:
			p->templateId = is_ipfix ? FID_CONNDIRECTION : FID_Q9_CONNDIRECTION;
			break;
		case FID_PACKET_REORDER:
		case FID_Q9_PACKET_REORDER:
			p->templateId = is_ipfix ? FID_PACKET_REORDER : FID_Q9_PACKET_REORDER;
			break;
		case FID_SERVICE_TYPE: 
		case FID_Q9_SERVICE_TYPE:
			p->templateId = is_ipfix ? FID_SERVICE_TYPE : FID_Q9_SERVICE_TYPE;
			break;
		case FID_PIM_COUNT:
		case FID_Q9_PIM_COUNT:
			p->templateId = is_ipfix ? FID_PIM_COUNT : FID_Q9_PIM_COUNT;
			break;
		case FID_RTP_JITTER_MEAN:
		case FID_Q9_RTP_JITTER_MEAN:
		  p->templateId = is_ipfix ? FID_RTP_JITTER_MEAN : FID_Q9_RTP_JITTER_MEAN;
			break;
		case FID_RTP_JITTER_STDV:
		case FID_Q9_RTP_JITTER_STDV:
		  p->templateId = is_ipfix ? FID_RTP_JITTER_STDV : FID_Q9_RTP_JITTER_STDV;
			break;
		case FID_RTP_JITTER_MIN:
		case FID_Q9_RTP_JITTER_MIN:
		  p->templateId = is_ipfix ? FID_RTP_JITTER_MIN : FID_Q9_RTP_JITTER_MIN;
			break;
		case FID_RTP_JITTER_MAX:
		case FID_Q9_RTP_JITTER_MAX:
		  p->templateId = is_ipfix ? FID_RTP_JITTER_MAX : FID_Q9_RTP_JITTER_MAX;
			break;
		case FID_RATE_1SEC_MAX:
		case FID_Q9_RATE_1SEC_MAX:
			p->templateId = is_ipfix ? FID_RATE_1SEC_MAX : FID_Q9_RATE_1SEC_MAX;
			break;
		case FID_RATE_1SEC_MIN:
		case FID_Q9_RATE_1SEC_MIN:
			p->templateId = is_ipfix ? FID_RATE_1SEC_MIN : FID_Q9_RATE_1SEC_MIN;
			break;
		case FID_RATE_100MS_MAX:
		case FID_Q9_RATE_100MS_MAX:
			p->templateId = is_ipfix ? FID_RATE_100MS_MAX : FID_Q9_RATE_100MS_MAX;
			break;
		case FID_RATE_100MS_MIN:
		case FID_Q9_RATE_100MS_MIN:
			p->templateId = is_ipfix ? FID_RATE_100MS_MIN : FID_Q9_RATE_100MS_MIN;
			break;
		case FID_RATE_10MS_MAX:
		case FID_Q9_RATE_10MS_MAX:
			p->templateId = is_ipfix ? FID_RATE_10MS_MAX : FID_Q9_RATE_10MS_MAX;
			break;
		case FID_RATE_10MS_MIN:
		case FID_Q9_RATE_10MS_MIN:
			p->templateId = is_ipfix ? FID_RATE_10MS_MIN : FID_Q9_RATE_10MS_MIN;
			break;
		case FID_RATE_1MS_MAX:
		case FID_Q9_RATE_1MS_MAX:
			p->templateId = is_ipfix ? FID_RATE_1MS_MAX : FID_Q9_RATE_1MS_MAX;
			break;
		case FID_RATE_1MS_MIN:
		case FID_Q9_RATE_1MS_MIN:
			p->templateId = is_ipfix ? FID_RATE_1MS_MIN : FID_Q9_RATE_1MS_MIN;
			break;
		case FID_TCPWIN_MAX:
		case FID_Q9_TCPWIN_MAX:
			p->templateId = is_ipfix ? FID_TCPWIN_MAX : FID_Q9_TCPWIN_MAX;
			break;
		case FID_TCPWIN_MIN:
		case FID_Q9_TCPWIN_MIN:
			p->templateId = is_ipfix ? FID_TCPWIN_MIN : FID_Q9_TCPWIN_MIN;
			break;
		case FID_TCPWIN_EFF:
		case FID_Q9_TCPWIN_EFF:
			p->templateId = is_ipfix ? FID_TCPWIN_EFF : FID_Q9_TCPWIN_EFF;
			break;
		case FID_MPEGTS_JITTER_MEAN:
		case FID_Q9_MPEGTS_JITTER_MEAN:
		  p->templateId = is_ipfix ? FID_MPEGTS_JITTER_MEAN : FID_Q9_MPEGTS_JITTER_MEAN;
			break;
		case FID_MPEGTS_DISCONTINUITY_COUNT:
		case FID_Q9_MPEGTS_DISCONTINUITY_COUNT:
			p->templateId = is_ipfix ? FID_MPEGTS_DISCONTINUITY_COUNT : FID_Q9_MPEGTS_DISCONTINUITY_COUNT;
			break;
		case FID_MPEGTS_TOTAL_COUNT:
		case FID_Q9_MPEGTS_TOTAL_COUNT:
			p->templateId = is_ipfix ? FID_MPEGTS_TOTAL_COUNT : FID_Q9_MPEGTS_TOTAL_COUNT;
			break;
		case FID_MPEGTS_JITTER_STDV:
		case FID_Q9_MPEGTS_JITTER_STDV:
			p->templateId = is_ipfix ? FID_MPEGTS_JITTER_STDV : FID_Q9_MPEGTS_JITTER_STDV;
			break;

		case FID_UNUSED_1:
		case FID_Q9_UNUSED_1:
			p->templateId = is_ipfix ? FID_UNUSED_1 : FID_Q9_UNUSED_1;
			break;

		case FID_UNUSED_2:
		case FID_Q9_UNUSED_2:
			p->templateId = is_ipfix ? FID_UNUSED_2 : FID_Q9_UNUSED_2;
			break;
		default:
			break;
		}
	}
}

/* ******************************************** */

static void copyInt8(u_int8_t t8, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax) {
    if((*outBufferBegin)+sizeof(t8) < (*outBufferMax)) {
	memcpy(&outBuffer[(*outBufferBegin)], &t8, sizeof(t8));
	(*outBufferBegin) += sizeof(t8);
    }
}

/* ******************************************** */

static void copyInt16(u_int16_t _t16, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax) {
  u_int16_t t16 = htons(_t16);

  if((*outBufferBegin)+sizeof(t16) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t16, sizeof(t16));
    (*outBufferBegin) += sizeof(t16);
  }
}

/* ******************************************** */

static void copyInt32(u_int32_t _t32, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax) {
  u_int32_t t32 = htonl(_t32);

  if((*outBufferBegin)+sizeof(t32) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t32, sizeof(t32));
    (*outBufferBegin) += sizeof(t32);
  }
}

static void copyInt64(u_int64_t _t64, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax) {
  u_int64_t t64 = htonll(_t64);

  if((*outBufferBegin)+sizeof(t64) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t64, sizeof(t64));
    (*outBufferBegin) += sizeof(t64);
  }
}

static void copyFloat(float _f, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax) {
  void *_t32 = &_f;
  u_int32_t t32 = htonl(*(u_int32_t *)_t32);

  if((*outBufferBegin)+sizeof(t32) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t32, sizeof(t32));
    (*outBufferBegin) += sizeof(t32);
  }
}


/* static void copyInt32Array(u_int32_t *_t32a, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax, u_int nelements) {
  u_int i;
  for(i=0; i<nelements; i++) {
    copyInt32(*(_t32a+i),outBuffer,outBufferBegin,outBufferMax);
  }
  } */

/*
 * Copies an int32 array into an array of uint8, by replacing the values
 * with relative terms. The sum will be 0xFF, unless all buckets are zero, when sum will be 0.
 */
static void copyInt32ArrayToRelativeInt8(u_int32_t *_t32a, char *outBuffer, 
					 u_int *outBufferBegin, 
					 __attribute__((__unused__)) u_int *outBufferMax, 
					 u_int nelements) {
  u_int32_t sum = 0;
  u_int i, assigned = 0;
  u_int8_t *outarray = (u_int8_t *)outBuffer+*outBufferBegin;
  for(i=0; i<nelements; i++) {
    sum += _t32a[i];
  }
  if (sum == 0)
    sum = 1;			/* 1 to avoid fp errors */

  if(sum > 0x7FFFFFFF) {
    /* Where sum is a huge value, take special care to get correct output */
    sum >>= 8;
    for(i=0; i<nelements; i++) {
      outarray[i] = _t32a[i]/sum;
      _t32a[i] = _t32a[i] % sum;
      assigned += outarray[i];
    }
  } else {
    for(i=0; i<nelements; i++) {
      outarray[i] = _t32a[i]*0xFF/sum;
      _t32a[i] = _t32a[i] % sum;
      assigned += outarray[i];
    }
  }
  /* Sum not yet 255 due to rounding. Assign to largest remainders */
  while (assigned < 0xFF) {
    unsigned int largest = 0, ilargest;
    /* Expecting about 4 rounds. Not much more work than qsort, and avoids function calls.
       This function shows up at just over 1% in a profile */
    for(i=0; i<nelements; i++) {
      if (_t32a[i] > largest) {
	largest = _t32a[i];
	ilargest = i;
	_t32a[i] = 1;
      }
    }
    if (largest == 0) {
      break;
    } else {
      outarray[ilargest]++;
      assigned++;
    }
  }
  (*outBufferBegin) += sizeof(u_int8_t)*nelements;
}

/* ******************************************** */

static void copyLen(void *str, int strLen, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax) {
  if((*outBufferBegin)+strLen < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], str, strLen);
    (*outBufferBegin) += strLen;
  }
}

/* ******************************************** */

static void copyIpV6(struct in6_addr ipv6, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax) {
  copyLen((char*)&ipv6, sizeof(ipv6), outBuffer, outBufferBegin, outBufferMax);
}

static void copyIpAddress(u_int8_t ipversion, IpAddress ipaddr, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax) {
  int strLen = (ipversion==6)?sizeof(ipaddr.ipType.ipv6):sizeof(ipaddr.ipType.ipv4);
  if(ipaddr.ipVersion==ipversion) {
    if(ipversion==4)
      copyInt32(ipaddr.ipType.ipv4, outBuffer, outBufferBegin, outBufferMax);
    else {      
      copyLen(((char*)&ipaddr.ipType.ipv6), sizeof(ipaddr.ipType.ipv6),
	      outBuffer, outBufferBegin, outBufferMax);
    }
  } else {
    /* Write empty data for address */
    if((*outBufferBegin)+strLen < (*outBufferMax)) {
      memset(&outBuffer[(*outBufferBegin)], 0, strLen);
      (*outBufferBegin) += strLen;      
    }
  }    
}


/* ****************************************************** */

static void 
exportPayload(np_ctxt_t *npctxt, HashBucket *myBucket, int direction,
	      __attribute__((__unused__)) V9TemplateId *theTemplate,
	      char *outBuffer, u_int *outBufferBegin,
	      u_int *outBufferMax) {
  int len, payloadLen;

  if(direction == 0)
    len = myBucket->src2dstPayloadLen;
  else
    len = myBucket->dst2srcPayloadLen;

  payloadLen = 0; /* Default */

  switch(myBucket->proto) {
  case IPPROTO_TCP:
    if((npctxt->tcpPayloadExport == 1)
       || ((npctxt->tcpPayloadExport == 2)
	   && ((myBucket->src2dstTcpFlags & TH_SYN)
	       || (myBucket->dst2srcTcpFlags & TH_SYN))))
      payloadLen = len;
    break;
  case IPPROTO_UDP:
    if(npctxt->udpPayloadExport == 1)
      payloadLen = len;
    break;
  case IPPROTO_ICMP:
    if(npctxt->icmpPayloadExport == 1)
      payloadLen = len;
    break;
  default:
    if(npctxt->otherPayloadExport == 1)
      payloadLen = len;
    break;
  }

  /*
  t16 = theTemplate->templateId;
  copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
  t16 = payloadLen;
  copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
  */

  if(payloadLen > 0)
    copyLen(direction == 0 ? myBucket->src2dstPayload : myBucket->dst2srcPayload,
	    payloadLen,
	    outBuffer, outBufferBegin, outBufferMax);

  /* Ensure that the proper number of bytes are output */
  payloadLen = PAYLOAD_EXCERPT_MAX-payloadLen;
  while(payloadLen-- > 0)
    copyInt8(0,outBuffer,outBufferBegin,outBufferMax);

}


/* FIXME: 
 * For DAG and other passive monitoring cards, this is correct.
 * For PCAP file or Ethernet, we should really just return 0.
 */
static
u_int16_t ifIdx(HashBucket *myBucket, int direction, int inputIf) {
  u_short ingress_interface, egress_interface;

  /* Normalize indices to 0 and 1 */
  ingress_interface =  myBucket->ifindex ? 1 : 0;
  egress_interface = ingress_interface ? 0 : 1;
 
  if (direction == 0)
    return inputIf ? ingress_interface : egress_interface;
  else
    return inputIf ? egress_interface : ingress_interface;
}

#define TIME_S 4294967296ULL
#define TIME_MS 4294967
#define TIME_US 4294
#define TIME_NS 4

/* ******************************************** */

/* All fields in ver9_templates *have* to have a case entry in the switch 
 * statement here. */
static void handleTemplate(np_ctxt_t *npctxt, V9TemplateId *theTemplate, 
			   char *outBuffer, u_int *outBufferBegin,
			   u_int *outBufferMax, char buildTemplate, int *numElements,
			   HashBucket *theFlow, int direction, int addTypeLen) {
  unsigned long res32;

  if((buildTemplate || addTypeLen)
     && (theTemplate->templateLen != 0)) {

    /* Instructed only to build the template; not build data packet. */
    u_int16_t t16;

    t16 = theTemplate->templateId;
    copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
    t16 = theTemplate->templateLen;
    copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);

    if(npctxt->netFlowVersion == 0x0a && theTemplate->templateId > 0x7FFF) {
      /* If template ID is over 0x7FFF, then we also must output an enterprise
       * ID for the IPFIX format. */
      copyInt32(npctxt->enterpriseId, outBuffer, outBufferBegin, outBufferMax);
    }
  }

  if(!buildTemplate) {
    switch(theTemplate->templateId) {
    case 1:
      copyInt64(direction==0?theFlow->src2dstOctetDeltaCount:theFlow->dst2srcOctetDeltaCount,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case 2:
      copyInt64(direction==0?theFlow->pktSent:theFlow->pktRcvd,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case 4:
      copyInt8(theFlow->proto, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 5:
      copyInt8(direction == 0 ? theFlow->src2dstTos : theFlow->dst2srcTos,
	       outBuffer, outBufferBegin, outBufferMax);
      break;
    case 6:
      copyInt8(direction == 0 ? theFlow->src2dstTcpFlags : theFlow->dst2srcTcpFlags,
	       outBuffer, outBufferBegin, outBufferMax);
      break;
    case 7:
      copyInt16(direction == 0 ? theFlow->sport : theFlow->dport,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case 8:
      copyIpAddress(4, direction == 0 ? theFlow->src : theFlow->dst,
		    outBuffer, outBufferBegin, outBufferMax);
      break;
    case 10: /* INPUT_SNMP */
      {
	u_short ifindex = ifIdx(theFlow, direction, 1);
#ifdef DEBUG_IFINDEX
        printf("INPUT_SNMP ");
        nprintf(stdout, "%sa -> %da", theFlow, direction);
        printf("direction=%d,  inputif=1, ifindex=%d\n", direction, ifindex);
#endif
        copyInt16(ifindex, outBuffer, outBufferBegin, outBufferMax);
	break;
      }
    case 11:
      copyInt16(direction == 1 ? theFlow->sport : theFlow->dport,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case 12:
      copyIpAddress(4, direction == 1 ? theFlow->src : theFlow->dst,
		    outBuffer, outBufferBegin, outBufferMax);
      break;
    case 14: /* OUTPUT_SNMP */
      {
	u_short ifindex = ifIdx(theFlow, direction, 0);
#ifdef DEBUG_IFINDEX
	printf("OUTPUT_SNMP ");
	nprintf(stdout, "%sa -> %da", theFlow, direction);
	printf("direction=%d,  inputif=0, ifindex=%d\n", direction, ifindex);
#endif
	copyInt16(ifindex, outBuffer, outBufferBegin, outBufferMax);
	break;
      }
    case 16:
      copyInt16(direction == 0 ? ip2AS(theFlow->src) : ip2AS(theFlow->dst), outBuffer, outBufferBegin, outBufferMax);
      break;
    case 17:
      copyInt16(direction == 1 ? ip2AS(theFlow->src) : ip2AS(theFlow->dst), outBuffer, outBufferBegin, outBufferMax);
      break;
    case 21:			/* LAST_SWITCHED */
    {
      unsigned long long ls = (direction == 1 ?
			       theFlow->lastSeenRcvd :
			       theFlow->lastSeenSent);
      unsigned long t = msTimeDiff(ls, npctxt->initialSniffTime);

#ifdef DEBUG_TIMESTAMP
      traceEvent(npctxt, TRACE_INFO, "%s. %s=%d, %s=%u.%u, %s=%u.%u, %s=%u\n",
		 "handleTemplate",
		 "direction", direction,
		 "theFlow->lastSeenRcvd", 
		 (unsigned long) (theFlow->lastSeenRcvd >> 32),
		 (unsigned long) (((theFlow->lastSeenRcvd & 0xffffffff) 
				   * 1000) / 4295),
		 "theFlow->lastSeenSent", 
		 (unsigned long) (theFlow->lastSeenSent >> 32),
		 (unsigned long)(( (theFlow->lastSeenSent & 0xffffffff)
				   * 1000) / 4295),
		 "t", t);
#endif
      copyInt32(t, outBuffer, outBufferBegin, outBufferMax);
      break;
    }
    case 22:			/* FIRST_SWITCHED */
    {
      unsigned long long fs = (direction == 1 ?
			       theFlow->firstSeenRcvd :
			       theFlow->firstSeenSent);
      unsigned long t = msTimeDiff(fs, npctxt->initialSniffTime);

#ifdef DEBUG_TIMESTAMP
      traceEvent(npctxt, TRACE_INFO, "%s. %s=%d, %s=%u.%u, %s=%u.%u, %s=%u\n",
		 "handleTemplate",
		 "direction", direction,
		 "theFlow->firstSeenRcvd", 
		 (unsigned long) (theFlow->firstSeenRcvd >> 32),
		 (unsigned long) (((theFlow->firstSeenRcvd & 0xffffffff)
				   * 1000) / 4295),
		 "theFlow->firstSeenSent", 
		 (unsigned long) (theFlow->firstSeenSent >> 32),
		 (unsigned long) (((theFlow->firstSeenSent & 0xffffffff)
				   * 1000) / 4295),
		 "t", t);
#endif
      copyInt32(t, outBuffer, outBufferBegin, outBufferMax);
      break;
    }
    case 25:
      copyInt16(direction==0?theFlow->src2dstMinPktSize:theFlow->dst2srcMinPktSize, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 26:
      copyInt16(direction==0?theFlow->src2dstMaxPktSize:theFlow->dst2srcMaxPktSize, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 27:
      copyIpAddress(6, direction == 0 ? theFlow->src : theFlow->dst,
		    outBuffer, outBufferBegin, outBufferMax);
      break;
    case 28:
      copyIpAddress(6, direction == 0 ? theFlow->dst : theFlow->src,
		    outBuffer, outBufferBegin, outBufferMax);
      break;
      /* 
	 FIXME: NOT IMPLEMENTED:
    case 29:
    case 30:
      copyInt8(0, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 31:
      copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 32:
      copyInt16(0, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 33:
      copyInt8(0, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 34:
      copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 35:
      copyInt8(0, outBuffer, outBufferBegin, outBufferMax);
      break;*/

    case 36: /* FLOW_ACTIVE_TIMEOUT */
      copyInt16(npctxt->lifetimeTimeout, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 37: /* FLOW_INACTIVE_TIMEOUT */
      copyInt16(npctxt->idleTimeout, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 38:
      copyInt8(engineType, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 39:
      copyInt8(engineId, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 40: /* TOTAL_BYTES_EXP */
      copyInt64(npctxt->exportedOctetTotalCount, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 41: /* TOTAL_PKTS_EXP */
      copyInt64(npctxt->exportedMessageTotalCount, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 42: /* TOTAL_FLOWS_EXP */
      copyInt64(npctxt->exportedFlowsTotalCount - npctxt->exportedFlowsSinceLastPkt,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case 52:
      copyInt8(direction==0?theFlow->src2dstMinTTL:theFlow->dst2srcMinTTL, 
	       outBuffer, outBufferBegin, outBufferMax);
      break;
    case 53:
      copyInt8(direction==0?theFlow->src2dstMaxTTL:theFlow->dst2srcMaxTTL, 
	       outBuffer, outBufferBegin, outBufferMax);
      break;
    case 60: /* IP_PROTOCOL_VERSION */
      copyInt8(4, outBuffer, outBufferBegin, outBufferMax); /* FIX */
      break;
/*
 * RFC 5102 Information Model for IPFIX
 *
 * 5.11.6.  flowDirection
 *
 *   Description:
 *      The direction of the Flow observed at the Observation Point.
 *      There are only two values defined.
 *
 *      0x00: ingress flow
 *      0x01: egress flow
*/
      /*
	case 61:
	copyInt8(direction, outBuffer, outBufferBegin, outBufferMax); / * FIX * /
	break;
      */
    case 64:
      copyInt32(direction==0?theFlow->optionsIPV6src2dst:theFlow->optionsIPV6dst2src,
		outBuffer, outBufferBegin, outBufferMax);
      break;

      /* nFlow Extensions */
    case 80:
      copyInt8(direction == 0 ? fragmentedPacketSrc2Dst(theFlow) : fragmentedPacketSrc2Dst(theFlow),
	       outBuffer, outBufferBegin, outBufferMax);
      break;
    case 81:
      copyLen(direction == 0 ? theFlow->src2dstFingerprint : theFlow->dst2srcFingerprint, FINGERPRINT_LEN,
	       outBuffer, outBufferBegin, outBufferMax);
      break;
    case 82:
      copyInt16(theFlow->vlanId, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 83:
      copyInt32(nwLatencyComputed(theFlow) ? theFlow->nwLatency >> 32 : 0, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 84:
      if (nwLatencyComputed(theFlow))
	res32 = (unsigned long) (((theFlow->nwLatency & 0xffffffff) * 1000)
				 / 4295);
      else
	res32 = 0;
      copyInt32(res32, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 85:
      if (applLatencyComputed(theFlow)) {
	unsigned long long src64;

	if (direction == 0)
	  src64 = theFlow->src2dstApplLatency;
	else
	  src64 = theFlow->dst2srcApplLatency;
	res32 = src64 >> 32;
      } else {
	res32 = 0;
      }
      copyInt32(res32, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 86:
      if (applLatencyComputed(theFlow)) {
	unsigned long long src64;

	if (direction == 0)
	  src64 = theFlow->src2dstApplLatency;
	else
	  src64 = theFlow->dst2srcApplLatency;
	res32 = (unsigned long) (((theFlow->nwLatency & 0xffffffff) * 1000) 
				 / 4295);
      } else {
	res32 = 0;
      }
      copyInt32(res32, outBuffer, outBufferBegin, outBufferMax);
      break;
      /*case 88: -- CHECK, this is 177/179 now?
      copyInt32(direction == 0 ? theFlow->src2dstIcmpFlags : theFlow->dst2srcIcmpFlags,
		outBuffer, outBufferBegin, outBufferMax);
		break;*/
    case 130:
      copyInt32(npctxt->exporterIpv4Address, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 131:
      copyIpV6(npctxt->exporterIpv6Address, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 136:
      copyInt8(theFlow->flowEndReason, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 145:
      copyInt16(npctxt->templateID, outBuffer, outBufferBegin, outBufferMax);
      break;
    case 148:
      copyInt32(direction==0?theFlow->src2dstflowid:theFlow->dst2srcflowid, 
		outBuffer, outBufferBegin, outBufferMax);
      break;
      
    case 149:
      copyInt32(npctxt->observationDomainID, outBuffer, outBufferBegin, outBufferMax);
      break;
      
    case 150: /* FLOW_START_SECONDS uint32 */
      copyInt32(direction == 1 ? (theFlow->firstSeenRcvd>>32) : (theFlow->firstSeenSent>>32), outBuffer,outBufferBegin,outBufferMax);
      break;
    case 151: /* FLOW_END_SECONDS uint32 */
      copyInt32(direction == 1 ? (theFlow->lastSeenRcvd>>32) : (theFlow->lastSeenSent>>32), outBuffer,outBufferBegin,outBufferMax);
      break;
    case 152: /* FLOW_START_MILLISECONDS uint64 */
      {
	u_int32_t msec = (direction == 1 ? (theFlow->firstSeenRcvd&0xFFFFFFFF) : (theFlow->firstSeenSent&0xFFFFFFFF))/TIME_MS;
	u_int32_t sec = (direction == 1 ? (theFlow->firstSeenRcvd>>32) : (theFlow->firstSeenSent>>32));
	copyInt64((u_int64_t)msec + (u_int64_t)sec*1000ull, outBuffer,outBufferBegin,outBufferMax);
      }
      break;
    case 153: /* FLOW_END_MILLISECONDS uint64 */
      {
	u_int32_t msec = (direction == 1 ? (theFlow->lastSeenRcvd&0xFFFFFFFF) : (theFlow->lastSeenSent&0xFFFFFFFF))/TIME_MS;
	u_int32_t sec = (direction == 1 ? (theFlow->lastSeenRcvd>>32) : (theFlow->lastSeenSent>>32));
	copyInt64((u_int64_t)msec + (u_int64_t)sec*1000ull, outBuffer,outBufferBegin,outBufferMax);
      }
      break;
    case 154: /* FLOW_START_MICROSECONDS uint64 */
      {
	u_int32_t usec = (direction == 1 ? (theFlow->firstSeenRcvd&0xFFFFFFFF) : (theFlow->firstSeenSent&0xFFFFFFFF))/TIME_US;
	u_int32_t sec = (direction == 1 ? (theFlow->firstSeenRcvd>>32) : (theFlow->firstSeenSent>>32));
	copyInt64((u_int64_t)usec + (u_int64_t)sec*1000000ull, outBuffer,outBufferBegin,outBufferMax);
      }
      break;
    case 155: /* FLOW_END_MICROSECONDS uint64 */
      {
	u_int32_t usec = (direction == 1 ? (theFlow->lastSeenRcvd&0xFFFFFFFF) : (theFlow->lastSeenSent&0xFFFFFFFF))/TIME_US;
	u_int32_t sec = (direction == 1 ? (theFlow->lastSeenRcvd>>32) : (theFlow->lastSeenSent>>32));
	copyInt64((u_int64_t)usec + (u_int64_t)sec*1000000ull, outBuffer,outBufferBegin,outBufferMax);
      }
      break;
    case 156: /* FLOW_START_NANOSECONDS uint64 */
      {
	u_int32_t nsec = (direction == 1 ? (theFlow->firstSeenRcvd&0xFFFFFFFF) : (theFlow->firstSeenSent&0xFFFFFFFF))/TIME_NS;
	u_int32_t sec = (direction == 1 ? (theFlow->firstSeenRcvd>>32) : (theFlow->firstSeenSent>>32));
	copyInt64((u_int64_t)nsec + (u_int64_t)sec*1000000000ull, outBuffer,outBufferBegin,outBufferMax);
      }
      break;
    case 157: /* FLOW_END_NANOSECONDS uint64 */
      {
	u_int32_t nsec = (direction == 1 ? (theFlow->lastSeenRcvd&0xFFFFFFFF) : (theFlow->lastSeenSent&0xFFFFFFFF))/TIME_NS;
	u_int32_t sec = (direction == 1 ? (theFlow->lastSeenRcvd>>32) : (theFlow->lastSeenSent>>32));
	copyInt64((u_int64_t)nsec + (u_int64_t)sec*1000000000ull, outBuffer,outBufferBegin,outBufferMax);
      }
      break;
    case 160:
      {
	u_int32_t ssec = npctxt->initialSniffTime>>32;
	u_int32_t stick= npctxt->initialSniffTime&0xFFFFFFFFull;
	u_int64_t initSniffTime = ((u_int64_t)ssec)*1000ull + stick/TIME_MS;
	copyInt64(initSniffTime,outBuffer, outBufferBegin, outBufferMax);
      }
      break;
    case 161: /* FLOW_DURATION_MILLISECONDS */
      if(direction==0)
	copyInt64(msTimeDiff(theFlow->lastSeenSent,theFlow->firstSeenSent),outBuffer, outBufferBegin, outBufferMax);
      else
	copyInt64(msTimeDiff(theFlow->lastSeenRcvd,theFlow->firstSeenRcvd),outBuffer, outBufferBegin, outBufferMax);
      break;
      case 162: /* FLOW_DURATION_MICROSECONDS */
      if(direction==0)
	copyInt64(usTimeDiff(theFlow->lastSeenSent,theFlow->firstSeenSent),outBuffer, outBufferBegin, outBufferMax);
      else
	copyInt64(usTimeDiff(theFlow->lastSeenRcvd,theFlow->firstSeenRcvd),outBuffer, outBufferBegin, outBufferMax);
      break;
    case 163:
      copyInt64(npctxt->numObservedFlows,outBuffer, outBufferBegin, outBufferMax);
      break;
    case 164: /* ignoredPacketTotalCount */
      {
	u_int64_t count = npctxt->ignoredPacketTotalCount;
	if(npctxt->hwinfo != NULL)
	  count += pktsDropped(npctxt);
	copyInt64(count, outBuffer, outBufferBegin, outBufferMax);
      }
      break;
    case 165: /* ignoredOctetTotalCount */
      copyInt64(npctxt->ignoredOctetTotalCount,outBuffer, outBufferBegin, outBufferMax);
      break;
    case 166: /* NOTSENT_FLOWS */
      copyInt64(npctxt->notsent_flows,outBuffer, outBufferBegin, outBufferMax);
      break;
    case 167: /* NOTSENT_PKTS */
      copyInt64(npctxt->notsent_pkts,outBuffer, outBufferBegin, outBufferMax);
      break;
    case 168: /* NOTSENT_OCTETS */
      copyInt64(npctxt->notsent_octets,outBuffer, outBufferBegin, outBufferMax);
      break;
    case 186: /* TCP_WINDOW */
      copyInt16(direction==0?theFlow->src2dstTcpWindowSize:theFlow->dst2srcTcpWindowSize,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case 190:
      copyInt16(direction==0?theFlow->src2dstPktlenIpv4:theFlow->dst2srcPktlenIpv4,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case 191:
      copyInt32(direction==0?theFlow->src2dstPayloadlenIpv6:theFlow->dst2srcPayloadlenIpv6,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case 207:
      copyInt8(theFlow->headerlengthIPv4,outBuffer, outBufferBegin, outBufferMax);
      break;
    case 208:
      copyInt64(direction==0?theFlow->optionsIPV4src2dst:theFlow->optionsIPV4dst2src,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case 209:
      copyInt64(direction==0?theFlow->src2dstTcpOpt:theFlow->dst2srcTcpOpt,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case 210: /* Padding, always 0 */
      copyInt8(0,outBuffer, outBufferBegin, outBufferMax);
      break;
    case FID_HISTOGRAM_PKT_LNGTH: /* HISTOGRAM_PKT_LNGTH */
    case FID_Q9_HISTOGRAM_PKT_LNGTH:
      copyInt32ArrayToRelativeInt8(direction==0?theFlow->src2dstPktSizeHistogram:theFlow->dst2srcPktSizeHistogram,outBuffer,outBufferBegin,outBufferMax,PKTSZ_HISTOGRAM_SLOTS);
      break;
    case FID_HISTOGRAM_PKT_DIST: /* HISTOGRAM_PKT_DIST */
    case FID_Q9_HISTOGRAM_PKT_DIST:
      copyInt32ArrayToRelativeInt8(direction==0?theFlow->src2dstPktDistHistogram:theFlow->dst2srcPktDistHistogram,outBuffer,outBufferBegin,outBufferMax,PKTDIST_HISTOGRAM_SLOTS);
      break;
    case FID_RATE_1SEC_MAX:
    case FID_Q9_RATE_1SEC_MAX:
      copyInt32(direction==0?theFlow->src2dstRateMax[BITRATE_1SEC]:theFlow->dst2srcRateMax[BITRATE_1SEC], outBuffer,outBufferBegin,outBufferMax);
      break;
    case FID_RATE_1SEC_MIN:
    case FID_Q9_RATE_1SEC_MIN:
      copyInt32(direction==0?theFlow->src2dstRateMin[BITRATE_1SEC]:theFlow->dst2srcRateMin[BITRATE_1SEC], outBuffer,outBufferBegin,outBufferMax);
      break;
    case FID_RATE_100MS_MAX:
    case FID_Q9_RATE_100MS_MAX:
      copyInt32(direction==0?theFlow->src2dstRateMax[BITRATE_100MS]:theFlow->dst2srcRateMax[BITRATE_100MS], outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_RATE_100MS_MIN:
    case FID_Q9_RATE_100MS_MIN:
      copyInt32(direction==0?theFlow->src2dstRateMin[BITRATE_100MS]:theFlow->dst2srcRateMin[BITRATE_100MS], outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_RATE_10MS_MAX:
    case FID_Q9_RATE_10MS_MAX:
      copyInt32(direction==0?theFlow->src2dstRateMax[BITRATE_10MS]:theFlow->dst2srcRateMax[BITRATE_10MS], outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_RATE_10MS_MIN:
    case FID_Q9_RATE_10MS_MIN:
      copyInt32(direction==0?theFlow->src2dstRateMin[BITRATE_10MS]:theFlow->dst2srcRateMin[BITRATE_10MS], outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_RATE_1MS_MAX:
    case FID_Q9_RATE_1MS_MAX:
      copyInt32(direction==0?theFlow->src2dstRateMax[BITRATE_1MS]:theFlow->dst2srcRateMax[BITRATE_1MS], outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_RATE_1MS_MIN:
    case FID_Q9_RATE_1MS_MIN:
      copyInt32(direction==0?theFlow->src2dstRateMin[BITRATE_1MS]:theFlow->dst2srcRateMin[BITRATE_1MS], outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_PAYLOAD:
    case FID_Q9_PAYLOAD:
      exportPayload(npctxt, theFlow, direction, theTemplate, 
		    outBuffer, outBufferBegin, outBufferMax);
      break;
    case FID_VAR_PKT_DIST:
    case FID_Q9_VAR_PKT_DIST:
      {
	float f = 0.0f;
	u_int64_t n;	
	if(direction==0) {
	  n = theFlow->pktSent;
	  if(n>1)
	    f = ((n*theFlow->src2dst_expval_pktdist_x2 - 
		  theFlow->src2dst_expval_pktdist_x*theFlow->src2dst_expval_pktdist_x) /
		 (n*(n-1)));
	} else {
	  n = theFlow->pktRcvd;
	  if(n>1)
	    f = ((n*theFlow->dst2src_expval_pktdist_x2 - 
		  theFlow->dst2src_expval_pktdist_x*theFlow->dst2src_expval_pktdist_x) /
		 (n*(n-1)));
	}	
	copyFloat(f, outBuffer,outBufferBegin, outBufferMax);
      }
      break;
    case FID_EXPVAL_PKT_DIST:
    case FID_Q9_EXPVAL_PKT_DIST:
      {
	float f = 0.0f;
	if(direction==0 && theFlow->pktSent>0)
	  f = (float)(theFlow->src2dst_expval_pktdist_x/(u_int64_t)theFlow->pktSent);
	else if(theFlow->pktRcvd>0)
	  f = (float)(theFlow->dst2src_expval_pktdist_x/(u_int64_t)theFlow->pktRcvd);
	copyFloat(f, outBuffer,outBufferBegin,outBufferMax);
      }
      break;
    case FID_VAR_PKT_LENGTH:
    case FID_Q9_VAR_PKT_LENGTH:
      {
	float f = 0.0f;
	u_int64_t n;
	if(direction==0) {
	  n = theFlow->pktSent;
	  if(n>1)
	    f = ((n*theFlow->src2dst_expval_pktlength_x2 - 
		  theFlow->src2dst_expval_pktlength_x*theFlow->src2dst_expval_pktlength_x) /
		 (n*(n-1)));
	} else {
	  n = theFlow->pktRcvd;
	  if(n>1)
	    f = ((n*theFlow->dst2src_expval_pktlength_x2 - 
		  theFlow->dst2src_expval_pktlength_x*theFlow->dst2src_expval_pktlength_x) /
		 (n*(n-1)));
	}	
	copyFloat(f, outBuffer,outBufferBegin, outBufferMax);
      }
      break;
    case FID_EXPVAL_PKT_LENGTH:
    case FID_Q9_EXPVAL_PKT_LENGTH:
      {
	float f = 0.0f;
	if(direction==0 && theFlow->pktSent>0)
	  f = (float)(theFlow->src2dst_expval_pktlength_x/(u_int64_t)theFlow->pktSent);
	else if(theFlow->pktRcvd>0)
	  f = (float)(theFlow->dst2src_expval_pktlength_x/(u_int64_t)theFlow->pktRcvd);
	copyFloat(f, outBuffer,outBufferBegin,outBufferMax);
      }
      break;
      
    case FID_SUM_PKT_DIST:
    case FID_Q9_SUM_PKT_DIST:
      copyInt64(direction==0?theFlow->src2dst_expval_pktdist_x:theFlow->dst2src_expval_pktdist_x, outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_SUM_PKT_LENGTH:
    case FID_Q9_SUM_PKT_LENGTH:
      copyInt64(direction==0?theFlow->src2dst_expval_pktlength_x:theFlow->dst2src_expval_pktlength_x, outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_QSUM_PKT_DIST:
    case FID_Q9_QSUM_PKT_DIST:
      copyInt64(direction==0?theFlow->src2dst_expval_pktdist_x2:theFlow->dst2src_expval_pktdist_x2, outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_QSUM_PKT_LENGTH:
    case FID_Q9_QSUM_PKT_LENGTH:
      copyInt64(direction==0?theFlow->src2dst_expval_pktlength_x2:theFlow->dst2src_expval_pktlength_x2, outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_CONNDIRECTION:
    case FID_Q9_CONNDIRECTION:
      {
	unsigned short flags = direction==0?theFlow->src2dstTcpFlagsFirst:
	  theFlow->dst2srcTcpFlagsFirst;
	
	if((flags & TH_SYN)!=0 && (flags & TH_ACK)==0) {
	  /* Connection request */
	  copyInt8(0, outBuffer, outBufferBegin,outBufferMax);
	} else if((flags & TH_SYN)!=0 && (flags & TH_ACK)!=0) {   
	  /* Connection request response */
	  copyInt8(1, outBuffer, outBufferBegin,outBufferMax);
	} else {
	  /* Unknown, perhaps in-sequence packet */
	  copyInt8(0xFF, outBuffer, outBufferBegin,outBufferMax);
	}
      }
      break;
    case FID_PACKET_REORDER:
    case FID_Q9_PACKET_REORDER:
      copyInt32(direction==0?theFlow->src2dst_num_packets_out_of_sequence:theFlow->dst2src_num_packets_out_of_sequence, outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_SERVICE_TYPE:
    case FID_Q9_SERVICE_TYPE:
      copyInt16(theFlow->serviceType, outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_RTCP_JITTER:
      copyInt32(theFlow->rtcp_jitter, outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_RTCP_LOSTFRACTION:
      copyInt8(theFlow->rtcp_lostfrac, outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_RTCP_LOSTPKTS:
      copyInt32(theFlow->rtcp_lostpkts, outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_RTCP_SEQCYCLES:
       copyInt16(theFlow->rtcp_cycles, outBuffer, outBufferBegin,outBufferMax);
      break;
    case FID_PIM_COUNT:
    case FID_Q9_PIM_COUNT:
      copyInt8(theFlow->pim_count, outBuffer, outBufferBegin, outBufferMax);
      break;
    case FID_RTP_JITTER_MEAN:
    case FID_Q9_RTP_JITTER_MEAN:
      {
	rtp_stat_t *rtpstat = (direction == 0) ? theFlow->rtp_a_stat : theFlow->rtp_b_stat;
	u_int32_t res_us = 0;

	if (rtpstat) {
	  double average = rtpstat->sum_jitter/rtpstat->njitter;

	  res_us = (u_int32_t) (average * 1e6 + 0.5);		/* microseconds */
#ifdef DEBUG_RTP
	  printf("%s: %d\n", "rtp jt mean", res_us);
#endif
	}
	copyInt32(res_us, outBuffer, outBufferBegin,outBufferMax);
      }
      break;
    case FID_RTP_JITTER_STDV:
    case FID_Q9_RTP_JITTER_STDV:
      {
	rtp_stat_t *rtpstat = (direction == 0) ? theFlow->rtp_a_stat : theFlow->rtp_b_stat;
	u_int32_t res_us = 0;

	if (rtpstat) {
	  double average = rtpstat->sum_jitter/rtpstat->njitter;
	  double stddev  = sqrt((rtpstat->sqsum_jitter - average*average) / rtpstat->njitter);

	  res_us = (u_int32_t) (stddev * 1e6 + 0.5); /* microseconds */
#ifdef DEBUG_RTP
	  printf("%s: %d\n", "rtp jt stdv", res_us);
#endif
	}
	copyInt32(res_us, outBuffer, outBufferBegin,outBufferMax);
      }
      break;
    case FID_RTP_JITTER_MIN:
    case FID_Q9_RTP_JITTER_MIN:
      {
	rtp_stat_t *rtpstat = (direction == 0) ? theFlow->rtp_a_stat : theFlow->rtp_b_stat;
	u_int32_t res_us = 0;

	if (rtpstat) {
	  if (rtpstat->min_jitter == 9999.) {
	    res_us = 0;
	  } else {
	    res_us = (u_int32_t) (rtpstat->min_jitter * 1e6 + 0.5); /* microseconds */
	  }
#ifdef DEBUG_RTP
	  printf("%s: %d\n", "rtp jt min", res_us);
#endif
	}
	copyInt32(res_us, outBuffer, outBufferBegin,outBufferMax);
      }
      break;
    case FID_RTP_JITTER_MAX:
    case FID_Q9_RTP_JITTER_MAX:
      {
	rtp_stat_t *rtpstat = (direction == 0) ? theFlow->rtp_a_stat : theFlow->rtp_b_stat;
	u_int32_t res_us = 0;

	if (rtpstat) {
	  res_us = (u_int32_t) (rtpstat->max_jitter * 1e6 + 0.5); /* microseconds */
#ifdef DEBUG_RTP
	  printf("%s: %d\n", "rtp jt max", res_us);
#endif
	}
	copyInt32(res_us, outBuffer, outBufferBegin,outBufferMax);
      }
      break;
    case FID_TCPWIN_MAX:
    case FID_Q9_TCPWIN_MAX:
      copyInt32(direction==0?theFlow->src2dstTcpWindowMax:theFlow->dst2srcTcpWindowMax,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case FID_TCPWIN_MIN:
    case FID_Q9_TCPWIN_MIN:
      copyInt32(direction==0?theFlow->src2dstTcpWindowMin:theFlow->dst2srcTcpWindowMin,
		outBuffer, outBufferBegin, outBufferMax);
      break;
    case FID_TCPWIN_EFF:
    case FID_Q9_TCPWIN_EFF:
      copyInt32(direction==0?theFlow->src2dstTcpwin_eff:theFlow->dst2srcTcpwin_eff,
		outBuffer, outBufferBegin, outBufferMax);
      break;

      /* FIXME: Should we choose a direction here? */
    case FID_MPEGTS_JITTER_MEAN:
    case FID_Q9_MPEGTS_JITTER_MEAN:
      {
	u_int32_t res_us = 0;

	if (theFlow->mpegts_stat && theFlow->serviceType == SERVICE_MPEGTS) {
	  res_us = (u_int32_t) (theFlow->mpegts_stat->pcr_jitter_mean * 1e6 + 0.5); /* microseconds */
	}
	copyInt32(res_us, outBuffer, outBufferBegin, outBufferMax);
      }
      break;

    case FID_MPEGTS_JITTER_STDV:
    case FID_Q9_MPEGTS_JITTER_STDV:
      {
	u_int32_t res_us = 0;

	if (theFlow->mpegts_stat && theFlow->serviceType == SERVICE_MPEGTS) {
	  res_us = (u_int32_t) (theFlow->mpegts_stat->pcr_jitter_stdv * 1e6 + 0.5); /* microseconds */
	}
	copyInt32(res_us, outBuffer, outBufferBegin, outBufferMax);
      }
      break;

    case FID_MPEGTS_DISCONTINUITY_COUNT:
    case FID_Q9_MPEGTS_DISCONTINUITY_COUNT:
      {
	int disconts  = 0;

	if (theFlow->mpegts_stat && theFlow->serviceType == SERVICE_MPEGTS) {
	  disconts = theFlow->mpegts_stat->disconts;
	}
	copyInt32(disconts, outBuffer, outBufferBegin, outBufferMax);
      }
      break;
      
    case FID_MPEGTS_TOTAL_COUNT:
    case FID_Q9_MPEGTS_TOTAL_COUNT:
      {
	int total_packets = 0;

	if (theFlow->mpegts_stat  && theFlow->serviceType == SERVICE_MPEGTS) {
	  total_packets = theFlow->mpegts_stat->total_packets;
	}
	copyInt32(total_packets, outBuffer, outBufferBegin, outBufferMax);
      }
      break;
      
    case FID_UNUSED_1:
    case FID_Q9_UNUSED_1:
      {
	u_int32_t res_us = 0;

	copyInt32(res_us, outBuffer, outBufferBegin, outBufferMax);
      }
      break;
      
    case FID_UNUSED_2:
    case FID_Q9_UNUSED_2:
      {
	u_int32_t res_us = 0;

	copyInt32(res_us, outBuffer, outBufferBegin, outBufferMax);
      }
      break;
      
    };

  }

  (*numElements) = (*numElements)+1;
  return;
}


/* ******************************************** */

void flowPrintf(np_ctxt_t *npctxt, V9TemplateId **templateList, 
		char *outBuffer,
		int *outBufferBegin, int *outBufferMax,
		int *numElements, char buildTemplate,
		HashBucket *theFlow, int direction,
		int addTypeLen) {
  int idx = 0;

  (*numElements) = 0;

  while(templateList[idx] != NULL) {
    handleTemplate(npctxt, templateList[idx], 
		   outBuffer, (unsigned int *)outBufferBegin, (unsigned int *)outBufferMax,
		   buildTemplate, numElements,
		   theFlow, direction, addTypeLen);
    idx++;
  }
}

/* ******************************************** */

static void
turnOnSpecialProcessing(np_ctxt_t *npctxt, u_int element) {
  switch(element) {
  case FID_PAYLOAD:
  case FID_Q9_PAYLOAD:
    npctxt->maxPayloadLen = PAYLOAD_EXCERPT_MAX;
    break;
  case FID_HISTOGRAM_PKT_LNGTH:
  case FID_Q9_HISTOGRAM_PKT_LNGTH:
    npctxt->histPktSizeEnabled = 1;
    break;
  case FID_HISTOGRAM_PKT_DIST:
  case FID_Q9_HISTOGRAM_PKT_DIST:
    npctxt->histPktDistEnabled = 1;

  case FID_RATE_1SEC_MAX:
  case FID_Q9_RATE_1SEC_MAX:
  case FID_RATE_1SEC_MIN:
  case FID_Q9_RATE_1SEC_MIN:
    npctxt->bitrateCalcEnabled |= 1;
    break;
  case FID_RATE_100MS_MAX:
  case FID_Q9_RATE_100MS_MAX:
  case FID_RATE_100MS_MIN:
  case FID_Q9_RATE_100MS_MIN:
    npctxt->bitrateCalcEnabled |= 2;
    break;
  case FID_RATE_10MS_MAX:
  case FID_Q9_RATE_10MS_MAX:
  case FID_RATE_10MS_MIN:
  case FID_Q9_RATE_10MS_MIN:
    npctxt->bitrateCalcEnabled |= 4;
    break;
  case FID_RATE_1MS_MAX:
  case FID_Q9_RATE_1MS_MAX:
  case FID_RATE_1MS_MIN:
  case FID_Q9_RATE_1MS_MIN:
    npctxt->bitrateCalcEnabled |= 8;
    break;
  case FID_EXPVAL_PKT_DIST:
  case FID_Q9_EXPVAL_PKT_DIST:
  case FID_VAR_PKT_LENGTH:
  case FID_Q9_VAR_PKT_LENGTH:
  case FID_EXPVAL_PKT_LENGTH:
  case FID_Q9_EXPVAL_PKT_LENGTH:
  case FID_SUM_PKT_DIST:
  case FID_Q9_SUM_PKT_DIST:
  case FID_SUM_PKT_LENGTH:
  case FID_Q9_SUM_PKT_LENGTH:
  case FID_QSUM_PKT_DIST:
  case FID_Q9_QSUM_PKT_DIST:
  case FID_QSUM_PKT_LENGTH:
  case FID_Q9_QSUM_PKT_LENGTH:
    npctxt->pktDistLengthStddevs = 1;
    break;
  /* Turn on service classification */
  case FID_SERVICE_TYPE:
  case FID_Q9_SERVICE_TYPE:
  case FID_RTP_JITTER_MEAN:
  case FID_Q9_RTP_JITTER_MEAN:
  case FID_RTP_JITTER_STDV:
  case FID_Q9_RTP_JITTER_STDV:
  case FID_RTP_JITTER_MIN:
  case FID_Q9_RTP_JITTER_MIN:
  case FID_RTP_JITTER_MAX:
  case FID_Q9_RTP_JITTER_MAX:
  case FID_MPEGTS_JITTER_STDV:
  case FID_MPEGTS_JITTER_MEAN:
  case FID_Q9_MPEGTS_JITTER_MEAN:
  case FID_MPEGTS_DISCONTINUITY_COUNT:
  case FID_Q9_MPEGTS_DISCONTINUITY_COUNT:
  case FID_MPEGTS_TOTAL_COUNT:
  case FID_Q9_MPEGTS_TOTAL_COUNT:
    npctxt->serviceClassification = 1;
    break;
  case FID_RTCP_JITTER:
  case FID_RTCP_LOSTFRACTION:
  case FID_RTCP_LOSTPKTS:
  case FID_RTCP_SEQCYCLES:
    npctxt->rtcp_enabled = 1;
    break;
  }
  return;
}


/* ******************************************** */

/* Maximum size of packets sent to collector.
 * Should not exceed platform's MTU.
 * Add around 64 bytes of NetFlow header. */
#define UDP_FLOWSET_MTU 1380

void 
compileTemplate(np_ctxt_t *npctxt, char *_fmt, 
		V9TemplateId **templateList, int templateElements) 
{
  int idx=0, endIdx, i, templateIdx;
  char fmt[1024], tmpChar, found;
  int sizePerFlow = 0;
  int capacityPerFlowSet=0;

  templateIdx = 0;
  snprintf(fmt, sizeof(fmt), "%s", _fmt);

  select_entspec_format(npctxt);

  while(fmt[idx] != '\0') {	/* scan format string characters */
    switch(fmt[idx]) {
    case '%':	        /* special format follows */
      endIdx = ++idx;
      while(fmt[endIdx] != '\0') {
	if((fmt[endIdx] == ' ') || (fmt[endIdx] == '%'))
	  break;
	else
	  endIdx++;
      }

      if((endIdx == (idx+1)) && (fmt[endIdx] == '\0')) return;
      tmpChar = fmt[endIdx]; fmt[endIdx] = '\0';

      /* We have user's format name in 'fmt'.
       * Find this format name in the template list, and output 
       * to 'templateList'. */
      i = 0, found = 0;
      while(ver9_templates[i].templateDescr != NULL) {
	if(strcmp(&fmt[idx], ver9_templates[i].templateDescr) == 0) {
	  templateList[templateIdx++] = &ver9_templates[i];

	  if((ver9_templates[i].templateId & 0x8000) != 0 && 
	     npctxt->enterpriseId == 0) {
	    traceEvent(npctxt, TRACE_WARNING, "Exporting information element %u with enterpriseId 0.", (unsigned int)ver9_templates[i].templateId);
	    traceEvent(npctxt, TRACE_WARNING, "Please add 'enterpriseid=nnn' to the [ipfixflib] section in "CONFDIR"/"CONF_FILE", where nnn is your organization's IANA enterprise number.");
	  }

	  /* Set nprobe context to do processing for this type of */
	  /* data (required i.e. for payload extraction) */
	  turnOnSpecialProcessing(npctxt, ver9_templates[i].templateId);
	  found = 1;
	  sizePerFlow += ver9_templates[i].templateLen;
	  break;
	}

	i++;
      }

      if(!found) {
	traceEvent(npctxt, TRACE_WARNING, "Unable to locate template '%s'. Discarded.", &fmt[idx]);
      }

      if(templateIdx >= templateElements) {
	templateList[templateIdx] = NULL;
	traceEvent(npctxt, TRACE_WARNING, "");
	traceEvent(npctxt, TRACE_WARNING, "WARNING: Unable to purge further templates (%d).", templateIdx);
	traceEvent(npctxt, TRACE_WARNING, "");
	break;
      }

      fmt[endIdx] = tmpChar;
      if(tmpChar == '%')
	idx = endIdx;
      else
	idx = endIdx+1;
      break;
    default:
      idx++;
      break;
    }
  }

  templateList[templateIdx] = NULL;

  /* Calculate the max number of frames that fit into one frame.
   * We want to do this, in order to avoid putting too much into
   * one UDP FlowSet, which results in data loss. */

  if(sizePerFlow > 0) {
    capacityPerFlowSet = UDP_FLOWSET_MTU/sizePerFlow;

    /* Ensure reasonable values for min/max num of packets in a FlowSet. */
    if(capacityPerFlowSet < 1)
      capacityPerFlowSet = 1;
    npctxt->maxNumFlowsPerPacket = capacityPerFlowSet;
    if(npctxt->maxNumFlowsPerPacket < npctxt->minNumFlowsPerPacket)
      npctxt->minNumFlowsPerPacket = npctxt->maxNumFlowsPerPacket;
  }


}

/* ******************************************** */

long unsigned int toMs(unsigned long long theTime) {
  return msTimeDiff(theTime, 0);
}

/* ****************************************************** */

u_int32_t msTimeDiff(unsigned long long end, unsigned long long begin) {
  unsigned long long diff = end - begin;
  unsigned long diff_sec  = diff >> 32;
  unsigned long diff_msec = (unsigned long) (diff & 0xffffffff) / 4294967;

  return diff_sec * 1000 + diff_msec;
}

u_int32_t usTimeDiff(unsigned long long end, unsigned long long begin) {
  unsigned long long diff = end - begin;
  unsigned long diff_sec  = diff >> 32;
  unsigned long diff_usec = (unsigned long) (diff & 0xffffffff) / 4295;

  return diff_sec * 1000000 + diff_usec;
}

unsigned long pktsDropped(np_ctxt_t *ctxt)
{
  long res;
  
  if (ctxt->hwinfo !=  NULL) {
    return 0;
  } else {
    res = ctxt->hwinfo->pkt_drop - ctxt->initialPktsDropped;

    if (res > 0) {
      return (unsigned long) res;
    } else {
      return ULONG_MAX + 1 + res;
    }
  }
}

/* ****************************************************** */
/* ****************************************************** */

#ifndef WIN32
int createCondvar(ConditionalVariable *condvarId) {
  int rc;

  rc = pthread_mutex_init(&condvarId->mutex, NULL);
  rc = pthread_cond_init(&condvarId->condvar, NULL);
  condvarId->predicate = 0;

  return(rc);
}

/* ************************************ */

void deleteCondvar(ConditionalVariable *condvarId) {
  pthread_mutex_destroy(&condvarId->mutex);
  pthread_cond_destroy(&condvarId->condvar);
}

/* ************************************ */

int waitCondvar(ConditionalVariable *condvarId) {
  int rc;

  if((rc = pthread_mutex_lock(&condvarId->mutex)) != 0)
    return rc;

  while(condvarId->predicate <= 0) {
    rc = pthread_cond_wait(&condvarId->condvar, &condvarId->mutex);
  }

  condvarId->predicate--;

  rc = pthread_mutex_unlock(&condvarId->mutex);

  return rc;
}
/* ************************************ */

int signalCondvar(ConditionalVariable *condvarId) {
  int rc;

  rc = pthread_mutex_lock(&condvarId->mutex);

  condvarId->predicate++;

  rc = pthread_mutex_unlock(&condvarId->mutex);
  rc = pthread_cond_signal(&condvarId->condvar);

  return rc;
}

#undef sleep /* Used by ntop_sleep */

#else /* WIN32 */

/* ************************************ */

int createCondvar(ConditionalVariable *condvarId) {
  condvarId->condVar = CreateEvent(NULL,  /* no security */
				   TRUE , /* auto-reset event (FALSE = single event, TRUE = broadcast) */
				   FALSE, /* non-signaled initially */
				   NULL); /* unnamed */
  InitializeCriticalSection(&condvarId->criticalSection);
  return(1);
}

/* ************************************ */

void deleteCondvar(ConditionalVariable *condvarId) {
  CloseHandle(condvarId->condVar);
  DeleteCriticalSection(&condvarId->criticalSection);
}

/* ************************************ */

int waitCondvar(ConditionalVariable *condvarId) {
  int rc;
#ifdef DEBUG_IPFIX
  traceEvent(npctxt, CONST_TRACE_INFO, "Wait (%x)...", condvarId->condVar);
#endif
  EnterCriticalSection(&condvarId->criticalSection);
  rc = WaitForSingleObject(condvarId->condVar, INFINITE);
  LeaveCriticalSection(&condvarId->criticalSection);

#ifdef DEBUG_IPFIX
  traceEvent(npctxt, CONST_TRACE_INFO, "Got signal (%d)...", rc);
#endif

  return(rc);
}

/* ************************************ */

int signalCondvar(ConditionalVariable *condvarId) {
#ifdef DEBUG_IPFIX
  traceEvent(npctxt, CONST_TRACE_INFO, "Signaling (%x)...", condvarId->condVar);
#endif
  return((int)PulseEvent(condvarId->condVar));
}

/* ************************************ */

/* Courtesy of Wies-Software <wies@wiessoft.de> */
unsigned long waitForNextEvent(unsigned long ulDelay /* ms */) {
  unsigned long ulSlice = 1000L; /* 1 Second */

  while ((myGlobals.capturePackets != FLAG_NTOPSTATE_TERM) && (ulDelay > 0L)) {
    if (ulDelay < ulSlice)
      ulSlice = ulDelay;
    Sleep(ulSlice);
    ulDelay -= ulSlice;
  }

  return ulDelay;
}

#define sleep(a /* sec */) waitForNextEvent(1000*a /* ms */)

#endif /* WIN32 */

unsigned int ntop_sleep(unsigned int secs) {
  unsigned int unsleptTime = secs, rest;

  while((rest = sleep(unsleptTime)) > 0)
    unsleptTime = rest;

  return(secs);
}

#endif /* __KERNEL__ */

/* ******************************************* */

HashBucket* getListHead(HashBucket **list) {
    HashBucket *bkt = *list;
    (*list) = bkt->next;

    return(bkt);
}

/* ******************************************* */

void addToList(HashBucket *bkt, HashBucket **list) {
  bkt->next = *list;
  (*list) = bkt;
}

void addToListEnd(HashBucket *bkt, HashBucket **list, HashBucket **listend) {
  bkt->next = NULL;
  if(*listend==NULL) {
    *list = *listend = bkt;
    return;
  }
  (*listend)->next = bkt;
  *listend = bkt;
}
