/*#define CHASE_CHAIN*/
/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998
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

#include "stdlib.h"
#include "string.h"
#include "setjmp.h"

#include <netinet/in.h>

#include "ethertype.h"
#include "nlpid.h"
#include "llc.h"
#include "gencode.h"

#include "pcap-namedb.h"

#define ETHERMTU	1500

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

/* Hack variable controlling what protocols are autocompleted
 * when protocol undefined.
 */ 
int gen_sctp_proto = 1;

static struct block *gen_linktype(int);
static struct block *gen_hostop(bpf_u_int32, bpf_u_int32, int, int, u_int, u_int);
static struct block *gen_host(bpf_u_int32, bpf_u_int32, int, int, int);
static struct block *gen_portop(int, int, int);
static struct block *gen_port(int, int, int);
static struct block *gen_portrangeop(int, int, int, int);
static struct block *gen_portrange(int, int, int, int);
static int lookup_proto(const char *, int);
static struct block *gen_proto(int, int, int);
static struct block *gen_ehostop(const u_char *, int);

/*
 * Generate code to match a particular packet type by matching the
 * link-layer type field or fields in the 802.2 LLC header.
 *
 * "proto" is an Ethernet type value, if > ETHERMTU, or an LLC SAP
 * value, if <= ETHERMTU.
 */
static struct block *
gen_linktype(proto)
        register int proto;
{
    /*
        switch (linktype) {
        case DLT_EN10MB:
        case DLT_C_HDLC:
        case DLT_FDDI:
        case DLT_IEEE802:
        case DLT_IEEE802_11:
        case DLT_IEEE802_11_RADIO_AVS:
        case DLT_IEEE802_11_RADIO:
        case DLT_PRISM_HEADER:
        case DLT_ATM_RFC1483:
        case DLT_ATM_CLIP:
        case DLT_IP_OVER_FC:
        case DLT_SUNATM:
        case DLT_LINUX_SLL:
        case DLT_SLIP:
        case DLT_SLIP_BSDOS:
        case DLT_RAW:
        case DLT_PPP:
        case DLT_PPP_PPPD:
        case DLT_PPP_SERIAL:
        case DLT_PPP_ETHER:
        case DLT_PPP_BSDOS:
        case DLT_NULL:
        case DLT_LOOP:
        case DLT_ENC:
        case DLT_PFLOG:
        case DLT_ARCNET:
        case DLT_ARCNET_LINUX:
        case DLT_LTALK:
        case DLT_FRELAY:
        case DLT_JUNIPER_MFR:
        case DLT_JUNIPER_MLFR:
        case DLT_JUNIPER_MLPPP:
        case DLT_JUNIPER_ATM1:
        case DLT_JUNIPER_ATM2:
        case DLT_JUNIPER_PPPOE:
        case DLT_JUNIPER_PPPOE_ATM:
        case DLT_JUNIPER_GGSN:
        case DLT_JUNIPER_ES:
        case DLT_JUNIPER_MONITOR:
        case DLT_JUNIPER_SERVICES:
        case DLT_JUNIPER_ETHER:
        case DLT_JUNIPER_PPP:
        case DLT_JUNIPER_FRELAY:
        case DLT_JUNIPER_CHDLC:
        case DLT_LINUX_IRDA:
        case DLT_DOCSIS:
        case DLT_LINUX_LAPD:
                bpf_error("unsupported link-layer type %d", linktype);
        }
        */

        return new_link_node(0, proto);
}

static struct block *
gen_hostop(addr, mask, dir, proto, src_off, dst_off)
        bpf_u_int32 addr;
        bpf_u_int32 mask;
        int dir, proto;
        u_int src_off, dst_off;
{
        struct block *b0, *b1;
        u_int offset;

        switch (dir) {

        case Q_SRC:
                offset = src_off;
                break;

        case Q_DST:
                offset = dst_off;
                break;

        case Q_AND:
                b0 = gen_hostop(addr, mask, Q_SRC, proto, src_off, dst_off);
                b1 = gen_hostop(addr, mask, Q_DST, proto, src_off, dst_off);
                return new_and_node(b0, b1);

        case Q_OR:
        case Q_DEFAULT:
                b0 = gen_hostop(addr, mask, Q_SRC, proto, src_off, dst_off);
                b1 = gen_hostop(addr, mask, Q_DST, proto, src_off, dst_off);
                return new_or_node(b0, b1);

        default:
                ERROR("gen_hostop fatal");
                abort();
        }
        b0 = gen_linktype(proto);

        b1 = new_host_node(addr, mask, dir, offset);
        b1 = new_and_node(b0, b1);

        return b1;
}

static struct block *
gen_host(addr, mask, proto, dir, type)
	bpf_u_int32 addr;
	bpf_u_int32 mask;
	int proto;
	int dir;
	int type;
{
	struct block *b0;
	const char *typestr;

	if (type == Q_NET)
		typestr = "net";
	else
		typestr = "host";

	switch (proto) {

	case Q_DEFAULT:
		b0 = gen_host(addr, mask, Q_IP, dir, type);
		/*
		 * Only check for non-IPv4 addresses if we're not
		 * checking MPLS-encapsulated packets.
		 */
                /*
		if (label_stack_depth == 0) {
			b1 = gen_host(addr, mask, Q_ARP, dir, type);
			gen_or(b0, b1);
			b0 = gen_host(addr, mask, Q_RARP, dir, type);
			gen_or(b1, b0);
		}
                */
		return b0;

	case Q_IP:
		return gen_hostop(addr, mask, dir, ETHERTYPE_IP, 12, 16);

	case Q_RARP:
		return gen_hostop(addr, mask, dir, ETHERTYPE_REVARP, 14, 24);

	case Q_ARP:
		return gen_hostop(addr, mask, dir, ETHERTYPE_ARP, 14, 24);

	case Q_TCP:
		bpf_error("'tcp' modifier applied to %s", typestr);

	case Q_SCTP:
		bpf_error("'sctp' modifier applied to %s", typestr);

	case Q_UDP:
		bpf_error("'udp' modifier applied to %s", typestr);

	case Q_ICMP:
		bpf_error("'icmp' modifier applied to %s", typestr);

	case Q_IGMP:
		bpf_error("'igmp' modifier applied to %s", typestr);

	case Q_IGRP:
		bpf_error("'igrp' modifier applied to %s", typestr);

	case Q_PIM:
		bpf_error("'pim' modifier applied to %s", typestr);

	case Q_VRRP:
		bpf_error("'vrrp' modifier applied to %s", typestr);

	case Q_ATALK:
		bpf_error("ATALK host filtering not implemented");

	case Q_AARP:
		bpf_error("AARP host filtering not implemented");

	case Q_DECNET:
		//return gen_dnhostop(addr, dir);
                bpf_error("DECNET host filtering not implemented");

	case Q_SCA:
		bpf_error("SCA host filtering not implemented");

	case Q_LAT:
		bpf_error("LAT host filtering not implemented");

	case Q_MOPDL:
		bpf_error("MOPDL host filtering not implemented");

	case Q_MOPRC:
		bpf_error("MOPRC host filtering not implemented");

#ifdef INET6
	case Q_IPV6:
		bpf_error("'ip6' modifier applied to ip host");

	case Q_ICMPV6:
		bpf_error("'icmp6' modifier applied to %s", typestr);
#endif /* INET6 */

	case Q_AH:
		bpf_error("'ah' modifier applied to %s", typestr);

	case Q_ESP:
		bpf_error("'esp' modifier applied to %s", typestr);

	case Q_ISO:
		bpf_error("ISO host filtering not implemented");

	case Q_ESIS:
		bpf_error("'esis' modifier applied to %s", typestr);

	case Q_ISIS:
		bpf_error("'isis' modifier applied to %s", typestr);

	case Q_CLNP:
		bpf_error("'clnp' modifier applied to %s", typestr);

	case Q_STP:
		bpf_error("'stp' modifier applied to %s", typestr);

	case Q_IPX:
		bpf_error("IPX host filtering not implemented");

	case Q_NETBEUI:
		bpf_error("'netbeui' modifier applied to %s", typestr);

	case Q_RADIO:
		bpf_error("'radio' modifier applied to %s", typestr);

	default:
                ERROR("gen_host fatal");
		abort();
	}
	/* NOTREACHED */
}

struct block *
gen_proto_abbrev(proto)
	int proto;
{
/*	struct block *b0;*/
	struct block *b1;

	switch (proto) {

	case Q_SCTP:
		b1 = gen_proto(IPPROTO_SCTP, Q_IP, Q_DEFAULT);
#ifdef INET6
                /*
		b0 = gen_proto(IPPROTO_SCTP, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
                */
#endif
		break;

	case Q_TCP:
		b1 = gen_proto(IPPROTO_TCP, Q_IP, Q_DEFAULT);
#ifdef INET6    /*
		b0 = gen_proto(IPPROTO_TCP, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
                */
#endif
		break;

	case Q_UDP:
		b1 = gen_proto(IPPROTO_UDP, Q_IP, Q_DEFAULT);
#ifdef INET6    /*
		b0 = gen_proto(IPPROTO_UDP, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
                */
#endif
		break;

	case Q_ICMP:
		b1 = gen_proto(IPPROTO_ICMP, Q_IP, Q_DEFAULT);
		break;

#ifndef	IPPROTO_IGMP
#define	IPPROTO_IGMP	2
#endif

	case Q_IGMP:
		b1 = gen_proto(IPPROTO_IGMP, Q_IP, Q_DEFAULT);
		break;

#ifndef	IPPROTO_IGRP
#define	IPPROTO_IGRP	9
#endif
	case Q_IGRP:
		b1 = gen_proto(IPPROTO_IGRP, Q_IP, Q_DEFAULT);
		break;

#ifndef IPPROTO_PIM
#define IPPROTO_PIM	103
#endif

	case Q_PIM:
		b1 = gen_proto(IPPROTO_PIM, Q_IP, Q_DEFAULT);
#ifdef INET6    /*
		b0 = gen_proto(IPPROTO_PIM, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
                */
#endif
		break;

#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP	112
#endif

	case Q_VRRP:
		b1 = gen_proto(IPPROTO_VRRP, Q_IP, Q_DEFAULT);
		break;

	case Q_IP:
		b1 =  gen_linktype(ETHERTYPE_IP);
		break;

	case Q_ARP:
		b1 =  gen_linktype(ETHERTYPE_ARP);
		break;

	case Q_RARP:
		b1 =  gen_linktype(ETHERTYPE_REVARP);
		break;

	case Q_LINK:
		bpf_error("link layer applied in wrong context");

	case Q_ATALK:
		b1 =  gen_linktype(ETHERTYPE_ATALK);
		break;

	case Q_AARP:
		b1 =  gen_linktype(ETHERTYPE_AARP);
		break;

	case Q_DECNET:
		b1 =  gen_linktype(ETHERTYPE_DN);
		break;

	case Q_SCA:
		b1 =  gen_linktype(ETHERTYPE_SCA);
		break;

	case Q_LAT:
		b1 =  gen_linktype(ETHERTYPE_LAT);
		break;

	case Q_MOPDL:
		b1 =  gen_linktype(ETHERTYPE_MOPDL);
		break;

	case Q_MOPRC:
		b1 =  gen_linktype(ETHERTYPE_MOPRC);
		break;

#ifdef INET6
	case Q_IPV6:
		b1 = gen_linktype(ETHERTYPE_IPV6);
		break;

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6	58
#endif
	case Q_ICMPV6:
		b1 = gen_proto(IPPROTO_ICMPV6, Q_IPV6, Q_DEFAULT);
		break;
#endif /* INET6 */

#ifndef IPPROTO_AH
#define IPPROTO_AH	51
#endif
	case Q_AH:
		b1 = gen_proto(IPPROTO_AH, Q_IP, Q_DEFAULT);
#ifdef INET6    /*
		b0 = gen_proto(IPPROTO_AH, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
                */
#endif
		break;

#ifndef IPPROTO_ESP
#define IPPROTO_ESP	50
#endif
	case Q_ESP:
		b1 = gen_proto(IPPROTO_ESP, Q_IP, Q_DEFAULT);
#ifdef INET6    /*
		b0 = gen_proto(IPPROTO_ESP, Q_IPV6, Q_DEFAULT);
		gen_or(b0, b1);
                */
#endif
		break;

	case Q_ISO:
		b1 = gen_linktype(LLCSAP_ISONS);
		break;

	case Q_ESIS:
		b1 = gen_proto(ISO9542_ESIS, Q_ISO, Q_DEFAULT);
		break;

	case Q_ISIS:
		b1 = gen_proto(ISO10589_ISIS, Q_ISO, Q_DEFAULT);
		break;

	case Q_ISIS_L1: /* all IS-IS Level1 PDU-Types */
	case Q_ISIS_L2: /* all IS-IS Level2 PDU-Types */
	case Q_ISIS_IIH: /* all IS-IS Hello PDU-Types */
	case Q_ISIS_LSP:
	case Q_ISIS_SNP:
	case Q_ISIS_CSNP:
	case Q_ISIS_PSNP:
            bpf_error("filter: ISIS filtering not implemented");

	case Q_CLNP:
		b1 = gen_proto(ISO8473_CLNP, Q_ISO, Q_DEFAULT);
		break;

	case Q_STP:
		b1 = gen_linktype(LLCSAP_8021D);
		break;

	case Q_IPX:
		b1 = gen_linktype(LLCSAP_IPX);
		break;

	case Q_NETBEUI:
		b1 = gen_linktype(LLCSAP_NETBEUI);
		break;

	case Q_RADIO:
		bpf_error("'radio' is not a valid protocol type");

	default:
                ERROR("gen_proto_abbrev fatal");
		abort();
	}
	return b1;
}

static struct block *
gen_portop(port, proto, dir)
        int port, proto, dir;
{
        struct block *b0, *b1, *tmp;


        /* ip proto 'proto' */
        /*b0 = gen_ipfrag(); TODO: ???*/
        b0 = new_proto_node(proto);

        switch (dir) {
        case Q_SRC:
                b1 = new_port_node(port, 0, Q_SRC);
                break;

        case Q_DST:
                b1 = new_port_node(port, 2, Q_DST);
                break;

        case Q_OR:
        case Q_DEFAULT:
                tmp = new_port_node(port, 0, Q_SRC);
                b1 = new_port_node(port, 2, Q_DST);
                b1 = new_or_node(tmp, b1);
                break;

        case Q_AND:
                tmp = new_port_node(port, 0, Q_SRC);
                b1 = new_port_node(port, 2, Q_DST);
                b1 = new_and_node(tmp, b1);
                break;

        default:
                ERROR("gen_portop fatal");
                abort();
        }
        return new_and_node(b0, b1);
}

static struct block *
gen_port(port, ip_proto, dir)
	int port;
	int ip_proto;
	int dir;
{
	struct block *b0, *b1, *tmp;

	/*
	 * ether proto ip
	 *
	 * For FDDI, RFC 1188 says that SNAP encapsulation is used,
	 * not LLC encapsulation with LLCSAP_IP.
	 *
	 * For IEEE 802 networks - which includes 802.5 token ring
	 * (which is what DLT_IEEE802 means) and 802.11 - RFC 1042
	 * says that SNAP encapsulation is used, not LLC encapsulation
	 * with LLCSAP_IP.
	 *
	 * For LLC-encapsulated ATM/"Classical IP", RFC 1483 and
	 * RFC 2225 say that SNAP encapsulation is used, not LLC
	 * encapsulation with LLCSAP_IP.
	 *
	 * So we always check for ETHERTYPE_IP.
	 */
	b0 =  gen_linktype(ETHERTYPE_IP);

	switch (ip_proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
		b1 = gen_portop(port, ip_proto, dir);
		break;

	case PROTO_UNDEF:
                tmp = gen_portop(port, IPPROTO_TCP, dir);
                b1 = gen_portop(port, IPPROTO_UDP, dir);
                b1 = new_or_node(tmp, b1);
                if (gen_sctp_proto != 0) {
                    tmp = gen_portop(port, IPPROTO_SCTP, dir);
                    b1 = new_or_node(tmp, b1);
                }
		break;

	default:
                ERROR("gen_port fatal");
		abort();
	}
        return new_and_node(b0, b1);
}

static struct block *
gen_portrangeop(port1, port2, proto, dir)
        int port1, port2;
        int proto;
        int dir;
{
        struct block *b0, *b1, *tmp;

        /* ip proto 'proto' */
        /*b0 = gen_ipfrag(); TODO: ??? */
        b0 = new_proto_node(proto);


        switch (dir) {
        case Q_SRC:
                b1 = new_portrange_node(port1, port2, 0, Q_SRC);
                break;

        case Q_DST:
                b1 = new_portrange_node(port1, port2, 2, Q_DST);
                break;

        case Q_OR:
        case Q_DEFAULT:
                tmp = new_portrange_node(port1, port2, 0, Q_SRC);
                b1 = new_portrange_node(port1, port2, 2, Q_DST);
                b1 = new_or_node(tmp, b1);
                break;

        case Q_AND:
                tmp = new_portrange_node(port1, port2, 0, Q_SRC);
                b1 = new_portrange_node(port1, port2, 2, Q_DST);
                b1 = new_and_node(tmp, b1);
                break;

        default:
                ERROR("gen_portrangeop fatal");
                abort();
        }
        return new_and_node(b0, b1);
}

static struct block *
gen_portrange(port1, port2, ip_proto, dir)
	int port1, port2;
	int ip_proto;
	int dir;
{
	struct block *b0, *b1, *tmp;

	/* link proto ip */
	b0 =  gen_linktype(ETHERTYPE_IP);

	switch (ip_proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_SCTP:
		b1 = gen_portrangeop(port1, port2, ip_proto, dir);
		break;

	case PROTO_UNDEF:
                tmp = gen_portrangeop(port1, port2, IPPROTO_TCP, dir);
                b1 = gen_portrangeop(port1, port2, IPPROTO_UDP, dir);
                b1 = new_or_node(tmp, b1);
                tmp = gen_portrangeop(port1, port2, IPPROTO_SCTP, dir);
                b1 = new_or_node(tmp, b1);
		break;

	default:
                ERROR("gen_portrange fatal");
		abort();
	}
        return new_and_node(b0, b1);
}

/*
 * Generate code that checks whether the packet is a packet for protocol
 * <proto> and whether the type field in that protocol's header has
 * the value <v>, e.g. if <proto> is Q_IP, it checks whether it's an
 * IP packet and checks the protocol number in the IP header against <v>.
 *
 * If <proto> is Q_DEFAULT, i.e. just "proto" was specified, it checks
 * against Q_IP and Q_IPV6.
 */
static struct block *
gen_proto(v, proto, dir)
        int v;
        int proto;
        int dir;
{
        struct block *b0, *b1;

        if (dir != Q_DEFAULT)
                bpf_error("direction applied to 'proto'");

        switch (proto) {
        case Q_DEFAULT:
#ifdef INET6
            /*
                b0 = gen_proto(v, Q_IP, dir);
                b1 = gen_proto(v, Q_IPV6, dir);
                gen_or(b0, b1);
                return b1;
            */
#else
                /*FALLTHROUGH*/
#endif
        case Q_IP:
                /*
                 * For FDDI, RFC 1188 says that SNAP encapsulation is used,
                 * not LLC encapsulation with LLCSAP_IP.
                 *
                 * For IEEE 802 networks - which includes 802.5 token ring
                 * (which is what DLT_IEEE802 means) and 802.11 - RFC 1042
                 * says that SNAP encapsulation is used, not LLC encapsulation
                 * with LLCSAP_IP.
                 *
                 * For LLC-encapsulated ATM/"Classical IP", RFC 1483 and
                 * RFC 2225 say that SNAP encapsulation is used, not LLC
                 * encapsulation with LLCSAP_IP.
                 *
                 * So we always check for ETHERTYPE_IP.
                 */

                b0 = gen_linktype(ETHERTYPE_IP);
#ifndef CHASE_CHAIN
                b1 = new_proto_node(v);
#else
                /*
                b1 = gen_protochain(v, Q_IP);
                */
#endif
                return new_and_node(b0, b1);

        case Q_ISO:
                bpf_error("ISO not supported");
        case Q_ISIS:
                bpf_error("ISIS not supported");

        case Q_ARP:
                bpf_error("arp does not encapsulate another protocol");
                /* NOTREACHED */

        case Q_RARP:
                bpf_error("rarp does not encapsulate another protocol");
                /* NOTREACHED */

        case Q_ATALK:
                bpf_error("atalk encapsulation is not specifiable");
                /* NOTREACHED */

        case Q_DECNET:
                bpf_error("decnet encapsulation is not specifiable");
                /* NOTREACHED */

        case Q_SCA:
                bpf_error("sca does not encapsulate another protocol");
                /* NOTREACHED */

        case Q_LAT:
                bpf_error("lat does not encapsulate another protocol");
                /* NOTREACHED */

        case Q_MOPRC:
                bpf_error("moprc does not encapsulate another protocol");
                /* NOTREACHED */

        case Q_MOPDL:
                bpf_error("mopdl does not encapsulate another protocol");
                /* NOTREACHED */

        case Q_LINK:
                return gen_linktype(v);

        case Q_UDP:
                bpf_error("'udp proto' is bogus");
                /* NOTREACHED */

        case Q_TCP:
                bpf_error("'tcp proto' is bogus");
                /* NOTREACHED */

        case Q_SCTP:
                bpf_error("'sctp proto' is bogus");
                /* NOTREACHED */

        case Q_ICMP:
                bpf_error("'icmp proto' is bogus");
                /* NOTREACHED */

        case Q_IGMP:
                bpf_error("'igmp proto' is bogus");
                /* NOTREACHED */

        case Q_IGRP:
                bpf_error("'igrp proto' is bogus");
                /* NOTREACHED */

        case Q_PIM:
                bpf_error("'pim proto' is bogus");
                /* NOTREACHED */

        case Q_VRRP:
                bpf_error("'vrrp proto' is bogus");
                /* NOTREACHED */

#ifdef INET6
                /*
        case Q_IPV6:
                b0 = gen_linktype(ETHERTYPE_IPV6);
                */
#ifndef CHASE_CHAIN
                /*
                b1 = gen_cmp(OR_NET, 6, BPF_B, (bpf_int32)v);
                */
#else
                /*
                b1 = gen_protochain(v, Q_IPV6);
                */
#endif
                /*
                gen_and(b0, b1);
                return b1;

        case Q_ICMPV6:
                bpf_error("'icmp6 proto' is bogus");
                */

#endif /* INET6 */

        case Q_AH:
                bpf_error("'ah proto' is bogus");

        case Q_ESP:
                bpf_error("'ah proto' is bogus");

        case Q_STP:
                bpf_error("'stp proto' is bogus");

        case Q_IPX:
                bpf_error("'ipx proto' is bogus");

        case Q_NETBEUI:
                bpf_error("'netbeui proto' is bogus");

        case Q_RADIO:
                bpf_error("'radio proto' is bogus");

        default:
                ERROR("gen_proto fatal");
                abort();
                /* NOTREACHED */
        }
        /* NOTREACHED */
}


static int
lookup_proto(name, proto)
        register const char *name;
        register int proto;
{
        register int v;

        switch (proto) {

        case Q_DEFAULT:
        case Q_IP:
        case Q_IPV6:
                v = pcap_nametoproto(name);
                if (v == PROTO_UNDEF)
                        bpf_error("unknown ip proto '%s'", name);
                break;

        case Q_LINK:
                /* XXX should look up h/w protocol type based on linktype */
                v = pcap_nametoeproto(name);
                if (v == PROTO_UNDEF) {
                        v = pcap_nametollc(name);
                        if (v == PROTO_UNDEF)
                                bpf_error("unknown ether proto '%s'", name);
                }
                break;

        case Q_ISO:
                if (strcmp(name, "esis") == 0)
                        v = ISO9542_ESIS;
                else if (strcmp(name, "isis") == 0)
                        v = ISO10589_ISIS;
                else if (strcmp(name, "clnp") == 0)
                        v = ISO8473_CLNP;
                else
                        bpf_error("unknown osi proto '%s'", name);
                break;

        default:
                v = PROTO_UNDEF;
                break;
        }
        return v;
}

struct block *
gen_scode(name, q)
        register const char *name;
        struct qual q;
{
        int proto = q.proto;
        int dir = q.dir;
        int tproto;
/*        u_char *eaddr;*/
        bpf_u_int32 mask, addr;
#ifndef INET6
        bpf_u_int32 **alist;
#else
        /*
        int tproto6;
        struct sockaddr_in *sin;
        struct sockaddr_in6 *sin6;
        struct addrinfo *res, *res0;
        struct in6_addr mask128;
        */
#endif /*INET6*/
        struct block *b, *tmp;
        int port, real_proto;
        int port1, port2;

        switch (q.addr) {

        case Q_NET:
                addr = pcap_nametonetaddr(name);
                if (addr == 0)
                        bpf_error("unknown network '%s'", name);
                /* Left justify network addr and calculate its network mask */
                mask = 0xffffffff;
                while (addr && (addr & 0xff000000) == 0) {
                        addr <<= 8;
                        mask <<= 8;
                }
                return gen_host(addr, mask, proto, dir, q.addr);

        case Q_DEFAULT:
        case Q_HOST:
                if (proto == Q_LINK) {
                        bpf_error("filter: link host type is not supported");
                        /*
                        switch (linktype) {

                        case DLT_EN10MB:
                                eaddr = pcap_ether_hostton(name);
                                if (eaddr == NULL)
                                        bpf_error(
                                            "unknown ether host '%s'", name);
                                b = gen_ehostop(eaddr, dir);
                                free(eaddr);
                                return b;
                        }
                        bpf_error("only ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel supports link-level host name");
                        */
                } else if (proto == Q_DECNET) {
                    bpf_error("filter: decnet host type is not supported");

                } else {

//#ifndef INET6
                        alist = pcap_nametoaddr(name);
                        if (alist == NULL || *alist == NULL)
                                bpf_error("unknown host '%s'", name);
                        tproto = proto;
                        if (/*off_linktype == (u_int)-1 &&*/ tproto == Q_DEFAULT)
                                tproto = Q_IP;
                        b = gen_host(**alist++, 0xffffffff, tproto, dir, q.addr);
                        while (*alist) {
                                tmp = gen_host(**alist++, 0xffffffff,
                                               tproto, dir, q.addr);
                                b = new_or_node(b, tmp);

                        }
                        return b;

//#else

                        /*
                        memset(&mask128, 0xff, sizeof(mask128));
                        res0 = res = pcap_nametoaddrinfo(name);
                        if (res == NULL)
                                bpf_error("unknown host '%s'", name);
                        b = tmp = NULL;
                        tproto = tproto6 = proto;
                        if (off_linktype == -1 && tproto == Q_DEFAULT) {
                                tproto = Q_IP;
                                tproto6 = Q_IPV6;
                        }
                        for (res = res0; res; res = res->ai_next) {
                                switch (res->ai_family) {
                                case AF_INET:
                                        if (tproto == Q_IPV6)
                                                continue;

                                        sin = (struct sockaddr_in *)
                                                res->ai_addr;
                                        tmp = gen_host(ntohl(sin->sin_addr.s_addr),
                                                0xffffffff, tproto, dir, q.addr);
                                        break;
                                case AF_INET6:
                                        if (tproto6 == Q_IP)
                                                continue;

                                        sin6 = (struct sockaddr_in6 *)
                                                res->ai_addr;
                                        tmp = gen_host6(&sin6->sin6_addr,
                                                &mask128, tproto6, dir, q.addr);
                                        break;
                                default:
                                        continue;
                                }
                                if (b)
                                        gen_or(b, tmp);
                                b = tmp;
                        }
                        freeaddrinfo(res0);
                        if (b == NULL) {
                                bpf_error("unknown host '%s'%s", name,
                                    (proto == Q_DEFAULT)
                                        ? ""
                                        : " for specified address family");
                        }
                        return b;
                */

//#endif /*INET6*/

                }

        case Q_PORT:
                if (proto != Q_DEFAULT &&
                    proto != Q_UDP && proto != Q_TCP && proto != Q_SCTP)
                        bpf_error("illegal qualifier of 'port'");
                if (pcap_nametoport(name, &port, &real_proto) == 0)
                        bpf_error("unknown port '%s'", name);
                if (proto == Q_UDP) {
                        if (real_proto == IPPROTO_TCP) {
                                bpf_error("port '%s' is tcp", name); }
                        else if (real_proto == IPPROTO_SCTP) {
                                bpf_error("port '%s' is sctp", name); }
                        else
                                /* override PROTO_UNDEF */
                                real_proto = IPPROTO_UDP;
                }
                if (proto == Q_TCP) {
                        if (real_proto == IPPROTO_UDP) {
                                bpf_error("port '%s' is udp", name); }

                        else if (real_proto == IPPROTO_SCTP) {
                                bpf_error("port '%s' is sctp", name); }
                        else
                                /* override PROTO_UNDEF */
                                real_proto = IPPROTO_TCP;
                }
                if (proto == Q_SCTP) {
                        if (real_proto == IPPROTO_UDP) {
                                bpf_error("port '%s' is udp", name); }

                        else if (real_proto == IPPROTO_TCP) {
                                bpf_error("port '%s' is tcp", name); }
                        else
                                /* override PROTO_UNDEF */
                                real_proto = IPPROTO_SCTP;
                }
#ifndef INET6
                return gen_port(port, real_proto, dir);
#else
                /*
            {
                struct block *b;
                b = gen_port(port, real_proto, dir);
                gen_or(gen_port6(port, real_proto, dir), b);
                return b;
            }
                */
#endif /* INET6 */

        case Q_PORTRANGE:
                if (proto != Q_DEFAULT &&
                    proto != Q_UDP && proto != Q_TCP && proto != Q_SCTP)
                        bpf_error("illegal qualifier of 'portrange'");
                if (pcap_nametoportrange(name, &port1, &port2, &real_proto) == 0)
                        bpf_error("unknown port in range '%s'", name);
                if (proto == Q_UDP) {
                        if (real_proto == IPPROTO_TCP) {
                                bpf_error("port in range '%s' is tcp", name); }
                        else if (real_proto == IPPROTO_SCTP) {
                                bpf_error("port in range '%s' is sctp", name); }
                        else
                                /* override PROTO_UNDEF */
                                real_proto = IPPROTO_UDP;
                }
                if (proto == Q_TCP) {
                        if (real_proto == IPPROTO_UDP) {
                                bpf_error("port in range '%s' is udp", name); }
                        else if (real_proto == IPPROTO_SCTP) {
                                bpf_error("port in range '%s' is sctp", name); }
                        else
                                /* override PROTO_UNDEF */
                                real_proto = IPPROTO_TCP;
                }
                if (proto == Q_SCTP) {
                        if (real_proto == IPPROTO_UDP) {
                                bpf_error("port in range '%s' is udp", name); }
                        else if (real_proto == IPPROTO_TCP) {
                                bpf_error("port in range '%s' is tcp", name); }
                        else
                                /* override PROTO_UNDEF */
                                real_proto = IPPROTO_SCTP;
                }
#ifndef INET6
                return gen_portrange(port1, port2, real_proto, dir);
#else
                /*
            {
                struct block *b;
                b = gen_portrange(port1, port2, real_proto, dir);
                gen_or(gen_portrange6(port1, port2, real_proto, dir), b);
                return b;
            }
                */
#endif /* INET6 */

        case Q_GATEWAY:
            /*
#ifndef INET6
                eaddr = pcap_ether_hostton(name);
                if (eaddr == NULL)
                        bpf_error("unknown ether host: %s", name);

                alist = pcap_nametoaddr(name);
                if (alist == NULL || *alist == NULL)
                        bpf_error("unknown host '%s'", name);
                b = gen_gateway(eaddr, alist, proto, dir);
                free(eaddr);
                return b;
#else
            */
                bpf_error("'gateway' not supported in this configuration");
//#endif /*INET6*/


        case Q_PROTO:
                real_proto = lookup_proto(name, proto);
                if (real_proto >= 0)
                        return gen_proto(real_proto, proto, dir);
                else
                        bpf_error("unknown protocol: %s", name);

        case Q_PROTOCHAIN:
            bpf_error("filter: protocol chaining is not supported");
            /*
                real_proto = lookup_proto(name, proto);
                if (real_proto >= 0)
                        return gen_protochain(real_proto, proto, dir);
                else
                        bpf_error("unknown protocol: %s", name);

            */
        case Q_UNDEF:
                syntax();
                /* NOTREACHED */
        }
        abort();
        /* NOTREACHED */
}

struct block *
gen_mcode(s1, s2, masklen, q)
	register const char *s1, *s2;
	register int masklen;
	struct qual q;
{
	register int nlen, mlen;
	bpf_u_int32 n, m;

	nlen = __pcap_atoin(s1, &n);
	/* Promote short ipaddr */
	n <<= 32 - nlen;

	if (s2 != NULL) {
		mlen = __pcap_atoin(s2, &m);
		/* Promote short ipaddr */
		m <<= 32 - mlen;
		if ((n & ~m) != 0)
			bpf_error("non-network bits set in \"%s mask %s\"",
			    s1, s2);
	} else {
		/* Convert mask len to mask */
		if (masklen > 32)
			bpf_error("mask length must be <= 32");
		if (masklen == 0) {
			/*
			 * X << 32 is not guaranteed by C to be 0; it's
			 * undefined.
			 */
			m = 0;
		} else
			m = 0xffffffff << (32 - masklen);
		if ((n & ~m) != 0)
			bpf_error("non-network bits set in \"%s/%d\"",
			    s1, masklen);
	}

	switch (q.addr) {

	case Q_NET:
		return gen_host(n, m, q.proto, q.dir, q.addr);

	default:
		bpf_error("Mask syntax for networks only");
		/* NOTREACHED */
	}
	/* NOTREACHED */
}

struct block *
gen_ncode(s, v, q)
	register const char *s;
	bpf_u_int32 v;
	struct qual q;
{
	bpf_u_int32 mask;
	int proto = q.proto;
	int dir = q.dir;
	register int vlen;

	if (s == NULL)
		vlen = 32;
	else if (q.proto == Q_DECNET)
		vlen = __pcap_atodn(s, &v);
	else
		vlen = __pcap_atoin(s, &v);

	switch (q.addr) {

	case Q_DEFAULT:
	case Q_HOST:
	case Q_NET:
		if (proto == Q_DECNET)
			return gen_host(v, 0, proto, dir, q.addr);
		else if (proto == Q_LINK) {
			bpf_error("illegal link layer address");
		} else {
			mask = 0xffffffff;
			if (s == NULL && q.addr == Q_NET) {
				/* Promote short net number */
				while (v && (v & 0xff000000) == 0) {
					v <<= 8;
					mask <<= 8;
				}
			} else {
				/* Promote short ipaddr */
				v <<= 32 - vlen;
				mask <<= 32 - vlen;
			}
			return gen_host(v, mask, proto, dir, q.addr);
		}

	case Q_PORT:
		if (proto == Q_UDP)
			proto = IPPROTO_UDP;
		else if (proto == Q_TCP)
			proto = IPPROTO_TCP;
		else if (proto == Q_SCTP)
			proto = IPPROTO_SCTP;
		else if (proto == Q_DEFAULT)
			proto = PROTO_UNDEF;
		else
			bpf_error("illegal qualifier of 'port'");

#ifndef INET6
		return gen_port((int)v, proto, dir);
#else
                /*
	    {
		struct block *b;
		b = gen_port((int)v, proto, dir);
		gen_or(gen_port6((int)v, proto, dir), b);
		return b;
	    }
                */
#endif /* INET6 */

	case Q_PORTRANGE:
		if (proto == Q_UDP)
			proto = IPPROTO_UDP;
		else if (proto == Q_TCP)
			proto = IPPROTO_TCP;
		else if (proto == Q_SCTP)
			proto = IPPROTO_SCTP;
		else if (proto == Q_DEFAULT)
			proto = PROTO_UNDEF;
		else
			bpf_error("illegal qualifier of 'portrange'");

#ifndef INET6
		return gen_portrange((int)v, (int)v, proto, dir);
#else
                /*
	    {
		struct block *b;
		b = gen_portrange((int)v, (int)v, proto, dir);
		gen_or(gen_portrange6((int)v, (int)v, proto, dir), b);
		return b;
	    }
                */
#endif /* INET6 */

	case Q_GATEWAY:
		bpf_error("'gateway' requires a name");
		/* NOTREACHED */

	case Q_PROTO:
		return gen_proto((int)v, proto, dir);

	case Q_PROTOCHAIN:
                bpf_error("filter: protocol chaining is not supported");
		//return gen_protochain((int)v, proto, dir);

	case Q_UNDEF:
		syntax();
                /* NOTREACHED */

	default:
                ERROR("gen_ncode fatal");
		abort();
		/* NOTREACHED */
	}
	/* NOTREACHED */
}

struct block *gen_ecode(eaddr, q)
       register const u_char *eaddr;
       struct qual q;
{

  if ((q.addr == Q_HOST || q.addr == Q_DEFAULT) && q.proto == Q_LINK) {
    /* case DLT_EN10MB: */
    return gen_ehostop(eaddr, (int)q.dir);
  }

  bpf_error("ethernet address used in non-ether expression");

  /* NOTREACHED */
  return NULL;
}

struct block *
gen_broadcast(proto)
	int proto;
{
	struct block *b0, *b1;
	static u_char ebroadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	switch (proto) {

	case Q_DEFAULT:
	case Q_LINK:
               /* case DLT_EN10MB: */
               return gen_ehostop(ebroadcast, Q_DST);

	case Q_IP:
		b0 = gen_linktype(ETHERTYPE_IP);
		//bpf_u_int32 hostmask = ~netmask; //Do not have host/netmask, can only match 255.255.255.255 broadcasts.
                b1 = gen_host(0xFFFFFFFF, 0xFFFFFFFF, Q_IP, Q_DST, Q_NET);
		return new_and_node(b0, b1);
	}

	bpf_error("only link-layer/IP broadcast filters supported");

	/* NOTREACHED */
	return NULL;
}

static struct block *
gen_ehostop(eaddr, dir)
	register const u_char *eaddr;
	register int dir;
{
	register struct block *b0, *b1;
        unsigned char mask[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	switch (dir) {
	case Q_SRC:
	case Q_DST:
		return new_ehost_node(eaddr, mask, dir);

	case Q_AND:
		b0 = gen_ehostop(eaddr, Q_SRC);
		b1 = gen_ehostop(eaddr, Q_DST);
		b1 = new_and_node(b0, b1);
		return b1;

	case Q_DEFAULT:
	case Q_OR:
		b0 = gen_ehostop(eaddr, Q_SRC);
		b1 = gen_ehostop(eaddr, Q_DST);
		b1 = new_or_node(b0, b1);
		return b1;
	}
	abort();
	/* NOTREACHED */
}

/*
 * support IEEE 802.1Q VLAN trunk over ethernet
 */
struct block *
gen_vlan(vlan_num)
	int vlan_num;
{
	struct	block	*b0, *b1;

	/* check for VLAN */
        b0 = gen_linktype(ETHERTYPE_8021Q);

	/* If a specific VLAN is requested, check VLAN id */
	if (vlan_num >= 0) {
                b1 = new_vlan_node(vlan_num);
                b0 = new_and_node(b0,b1);
	}

	return (b0);
}

/*
 * support for MPLS
 */
struct block *
gen_mpls(label_num)
	int label_num;
{
	struct	block	*b0,*b1;

        b0 = gen_linktype(ETHERTYPE_MPLS);

	/* If a specific MPLS label is requested, check it */
	if (label_num >= 0) {
		b1 = new_mpls_node(label_num);
		b0 = new_and_node(b0,b1);
	}

	return (b0);
}

struct block *
gen_multicast(proto)
	int proto;
{
	register struct block *b0, *b1;
        static u_char emulticast[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };

	switch (proto) {

	case Q_DEFAULT:
	case Q_LINK:
                /*case  DLT_EN10MB:*/
                /* ether[0] & 1 != 0 */
                return new_ehost_node(emulticast, emulticast, Q_DST);

	case Q_IP:
		b0 = gen_linktype(ETHERTYPE_IP);
                b1 = gen_host(0xE0000000, 0xF0000000, Q_IP, Q_DST, Q_NET);
		return new_and_node(b0, b1);

	}

	bpf_error("link-layer multicast filters supported only on ethernet.");

	/* NOTREACHED */
	return NULL;
}

/*
 * Used for ICMP code/type, TCP flags and ETHER type
 */
struct block *
gen_type(proto, type, val)
  int proto;
  int type;
  int val;
{

  struct block *b0, *b1;

  switch(proto) {
    case Q_LINK:
      if (val < 0) {
        bpf_error("No Ethertype set.");
      }
      if (val > 0xFFFF) {
        bpf_error("Error: Too big value set for ethertype. Ethertype is 2 bytes (16 bits).");
      }

      return new_ethertype_node(val);

    case Q_TCP:
      if (val < 0) {
        bpf_error("No TCP flags value set.");
      }

      b0 = new_proto_node(proto);
      b1 = new_type_node(proto, type, val);

      return new_and_node(b0, b1);

    case Q_ICMP:
      if (type == Q_TYPE) {
        if (val < 0) {
          bpf_error("No ICMP type value set.");
        }

        b0 = new_proto_node(IPPROTO_ICMP);
        b1 = new_type_node(proto, type, val);

        return new_and_node(b0, b1);
      }
      else if (type == Q_CODE) {
        if (val < 0) {
          bpf_error("No ICMP code value set.");
        }

        b0 = new_proto_node(IPPROTO_ICMP);
        b1 = new_type_node(proto, type, val);

        return new_and_node(b0, b1);
      }
      else {
        bpf_error("Can only set type or code for ICMP.");
      }

    default:
      bpf_error("Can only set type/code for ICMP or flags for TCP.");
  }

  /* NOT REACHED */
  return NULL;
}
