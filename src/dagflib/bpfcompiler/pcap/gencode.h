/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * ATM support:
 *
 * Copyright (c) 1997 Yen Yen Lim and North Dakota State University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Yen Yen Lim and
 *      North Dakota State University
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "bpf_node.h"
#include "bpf_compile.h"

#define bpf_u_int32 u_int32_t
#define block node



#ifndef HAVE___ATTRIBUTE__
#define __attribute__(x)
#endif /* HAVE___ATTRIBUTE__ */

/* Address qualifiers. */

#define Q_HOST		1
#define Q_NET		2
#define Q_PORT		3
#define Q_GATEWAY	4
#define Q_PROTO		5
#define Q_PROTOCHAIN	6
#define Q_PORTRANGE	7

/* Protocol qualifiers. */

#define Q_LINK		1
#define Q_IP		2
#define Q_ARP		3
#define Q_RARP		4
#define Q_SCTP		5
#define Q_TCP		6
#define Q_UDP		7
#define Q_ICMP		8
#define Q_IGMP		9
#define Q_IGRP		10


#define	Q_ATALK		11
#define	Q_DECNET	12
#define	Q_LAT		13
#define Q_SCA		14
#define	Q_MOPRC		15
#define	Q_MOPDL		16


#define Q_IPV6		17
#define Q_ICMPV6	18
#define Q_AH		19
#define Q_ESP		20

#define Q_PIM		21
#define Q_VRRP		22

#define Q_AARP		23

#define Q_ISO		24
#define Q_ESIS		25
#define Q_ISIS		26
#define Q_CLNP		27

#define Q_STP		28

#define Q_IPX		29

#define Q_NETBEUI	30

/* IS-IS Levels */
#define Q_ISIS_L1       31
#define Q_ISIS_L2       32
/* PDU types */
#define Q_ISIS_IIH      33
#define Q_ISIS_LAN_IIH  34
#define Q_ISIS_PTP_IIH  35
#define Q_ISIS_SNP      36
#define Q_ISIS_CSNP     37
#define Q_ISIS_PSNP     38
#define Q_ISIS_LSP      39

#define Q_RADIO		40

/* Directional qualifiers. */

#define Q_SRC		1
#define Q_DST		2
#define Q_OR		3
#define Q_AND		4

#define Q_DEFAULT	0
#define Q_UNDEF		255

/* ATM types */
#define A_METAC		22	/* Meta signalling Circuit */
#define A_BCC		23	/* Broadcast Circuit */
#define A_OAMF4SC	24	/* Segment OAM F4 Circuit */
#define A_OAMF4EC	25	/* End-to-End OAM F4 Circuit */
#define A_SC		26	/* Signalling Circuit*/
#define A_ILMIC		27	/* ILMI Circuit */
#define A_OAM		28	/* OAM cells : F4 only */
#define A_OAMF4		29	/* OAM F4 cells: Segment + End-to-end */
#define A_LANE		30	/* LANE traffic */
#define A_LLC		31	/* LLC-encapsulated traffic */

/* Based on Q.2931 signalling protocol */
#define A_SETUP		41	/* Setup message */
#define A_CALLPROCEED	42	/* Call proceeding message */
#define A_CONNECT	43	/* Connect message */
#define A_CONNECTACK	44	/* Connect Ack message */
#define A_RELEASE	45	/* Release message */
#define A_RELEASE_DONE	46	/* Release message */

/* ATM field types */
#define A_VPI		51
#define A_VCI		52
#define A_PROTOTYPE	53
#define A_MSGTYPE	54
#define A_CALLREFTYPE	55

#define A_CONNECTMSG	70	/* returns Q.2931 signalling messages for
				   establishing and destroying switched
				   virtual connection */
#define A_METACONNECT	71	/* returns Q.2931 signalling messages for
				   establishing and destroying predefined
				   virtual circuits, such as broadcast
				   circuit, oamf4 segment circuit, oamf4
				   end-to-end circuits, ILMI circuits or
				   connection signalling circuit. */

/*MTP3 field types */
#define M_SIO 1
#define M_OPC 2
#define M_DPC 3
#define M_SLS 4


struct qual {
	unsigned char addr;
	unsigned char proto;
	unsigned char dir;
	unsigned char pad;
};

struct block *gen_scode(const char *, struct qual);
struct block *gen_mcode(const char *, const char *, int, struct qual);
struct block *gen_ncode(const char *, bpf_u_int32, struct qual);
struct block *gen_ecode(const u_char *, struct qual);
struct block *gen_proto_abbrev(int);
struct block *gen_broadcast(int);
struct block *gen_multicast(int);
struct block *gen_vlan(int);
struct block *gen_mpls(int);
struct block *gen_type(int, int, int);
