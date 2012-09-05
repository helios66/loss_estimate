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

/* ********************************** */


extern u_char ignoreAS;
#ifndef WIN32
extern int useSyslog;
#endif
extern int traceLevel;
extern unsigned long long actTime;
extern u_short engineType, engineId;

#ifdef __KERNEL__
#define printf printk
#define free(a)   kfree(a)
#define malloc(a) kmalloc(a, GFP_ATOMIC /* GFP_KERNEL */)
#endif

/* ********************************** */
extern char* _intoa(IpAddress addr, char* buf, u_short bufLen);
extern char* _intoaV4(unsigned int addr, char* buf, u_short bufLen);
extern char* formatTraffic(float numBits, int bits, char *buf);
extern u_char ttlPredictor(u_char x);
extern char* proto2name(u_short proto);
extern void setPayload(np_ctxt_t *npctxt, HashBucket *bkt, 
		       u_char *payload, int payloadLen, int direction);
extern void updateApplLatency(u_short proto, HashBucket *bkt,
			      int direction, unsigned long long stamp,
			      u_int8_t icmpType);
extern void updateTcpFlags(HashBucket *bkt, int direction,
			   unsigned long long stamp, u_int8_t flags,
			   u_char *fingerprint, u_char tos);
extern void addPktToHash(np_ctxt_t *npctxt,
			 u_short proto, u_char isFragment, u_short numPkts,
			 u_char tos, IpAddress src, u_short sport,
			 IpAddress dst, u_short dport, u_int  len,
			 unsigned long long stamp, u_short ifindex, u_int8_t flags,
			 u_int8_t icmpType, u_char *fingerprint,
			 u_char *payload, int payloadLen,
			 u_int headerLen, u_int64_t v4_options, 
			 u_int64_t tcp_options, u_char ttl,
			 u_int32_t seqnum, u_int32_t acknum,
			 u_int is_pim, u_int16_t tcpWindowSize,
			 u_char tcpWindowScale);
extern void printICMPflags(u_int32_t flags, char *icmpBuf, int icmpBufLen);
extern void printFlow(np_ctxt_t *npctxt, HashBucket *theFlow, int direction);
extern int isFlowExpired(np_ctxt_t *npctxt, HashBucket *myBucket, time_t theTime);
extern void printBucket(HashBucket *myBucket);
extern void walkHash(np_ctxt_t *npctxt, int flushHash);

/* nprobe.c or nprobe_mod.c */
extern void queueBucketToExport(np_ctxt_t *npctxt, HashBucket *myBucket);
