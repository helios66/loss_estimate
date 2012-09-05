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

#include "nprobe.h"
#include "nprobe-priv.h"
#include "ifp-priv.h"
#include "mapidflib.h"

/* ******* Copy mapid_pkthdr_t from mapidlib.h for convenience ******* */
/* (we should include it directly, but there are conflicts which would need 
 * to be resolved first).
 */
//typedef struct mapid_pkthdr {
//  unsigned long long ts; /* 64-bit timestamp of packet*/
//  unsigned short ifindex; /* Interface index */
//  unsigned caplen;     /* length of portion present */
//  unsigned wlen;        /* length this packet (off wire) */
//} mapid_pkthdr_t;
#include "npktproc.h"

/*
 * pcap_pkthdr is 
 *	struct timeval ts;	 
 *	bpf_u_int32 caplen;	 
 *	bpf_u_int32 len;
 */

/* orig:
 * void processPacket(u_char *_deviceId,
 *		   const struct pcap_pkthdr *h,
 *		   const u_char *p) {
 * where p is content.
 */
void 
nprobeProcessPacket(void *ctxt, mapid_pkthdr_t *pkt_head, const void *pkt) 
{
  u_int caplen = pkt_head->caplen, length = pkt_head->wlen, offset;
  u_short eth_type, off=0, numPkts = 1;
  u_int8_t flags, proto;
  u_int32_t seqnum = 0, acknum = 0;
  struct ip ip;
  struct ip6_hdr ipv6;
  struct tcphdr tp;
  unsigned char *payload;
  int payloadLen; /* Do not set it to unsigned */
  u_char fingerprint[FINGERPRINT_LEN+1];
  IpAddress src, dst;
  u_char isFragment = 0;
  np_ctxt_t *npctxt = (np_ctxt_t *)ctxt;
  u_int64_t v4_options = 0;
  u_int64_t tcp_options = 0;
  u_int32_t tcpWindowSize = 0;
  /*u_int32_t v6_options = 0;*/
  u_int hlen;    /* IPv4/6 header length */
  u_char ttl;
  u_int is_pim = 0;
  u_int plen;
  u_short sport, dport;
  u_int ehshift;
  u_int estimatedLen;
  u_int16_t icmp_type = 0;
  u_char tcpWindowScale = -1;

  npctxt->totalPkts++,   npctxt->totalBytes   += length;
  npctxt->currentPkts++, npctxt->currentBytes += length;

  switch(npctxt->hwinfo->link_type) {
  case DLT_EN10MB: 
    if(caplen < sizeof(struct ether_header)) {
      npctxt->ignoredPacketTotalCount = npctxt->ignoredPacketTotalCount + 1;
      npctxt->ignoredOctetTotalCount = npctxt->ignoredOctetTotalCount + length;
      return;
    }
    eth_type = ntohs(((struct ether_header *)pkt)->ether_type);

    if((eth_type == ETHERTYPE_IP) || (eth_type == ETHERTYPE_IPV6))
      ehshift = sizeof(struct ether_header);
    else if(eth_type == ETHERTYPE_VLAN)
      ehshift = sizeof(struct ether_vlan_header);
    else
      ehshift = NULL_HDRLEN;

    break;  
  case DLT_C_HDLC:
    if(caplen < HLDC_HDRLEN) {
      npctxt->ignoredPacketTotalCount = npctxt->ignoredPacketTotalCount + 1;
      npctxt->ignoredOctetTotalCount = npctxt->ignoredOctetTotalCount + length;
      return;
    }
    eth_type = ntohs(*(unsigned short *)((char *)pkt+2));    

    ehshift = NULL_HDRLEN;

    break;
  default:
    ehshift = 0;
#ifdef DEBUG_IPFIX
    if(npctxt->traceMode)
      traceEvent(npctxt, TRACE_WARNING, "Unknown link type: 0x%X (%d)",
		 link_type, link_type);
#endif
    return;
  }


  switch(eth_type) {
  case ETHERTYPE_IP:
    memcpy(&ip, (char *)pkt+ehshift, sizeof(struct ip));
    if(ip.ip_v != 4) {
      npctxt->ignoredPacketTotalCount = npctxt->ignoredPacketTotalCount + 1;
      npctxt->ignoredOctetTotalCount = npctxt->ignoredOctetTotalCount + length;
      return; /* IP v4 only */
    }
    estimatedLen = ehshift+htons(ip.ip_len);
    hlen = (u_int)ip.ip_hl * 4;
    ttl = ip.ip_ttl;
    
    src.ipVersion = 4, dst.ipVersion = 4;
    if(npctxt->ignoreIpAddresses) {
      src.ipType.ipv4 = 0; /* 0.0.0.0 */
      dst.ipType.ipv4 = 0; /* 0.0.0.0 */
    } else {
      src.ipType.ipv4 = ntohl(ip.ip_src.s_addr);
      dst.ipType.ipv4 = ntohl(ip.ip_dst.s_addr);
    }
    
    proto = ip.ip_p;
    off = ntohs(ip.ip_off);
    isFragment = (off & 0x3fff) ? 1 : 0;
    
    
    /* Parse IPv4 header options, if they exist */
    if(hlen >= 24) {
      u_int olen = 4;
      if(hlen >= 28)
	olen = 8;
      memcpy(&v4_options,(char *)pkt+ehshift+sizeof(struct ip), olen);	  
    }
    break;
  
  case ETHERTYPE_IPV6:
    memcpy(&ipv6, (char *)pkt+ehshift, sizeof(struct ip6_hdr));
    if(((ipv6.ip6_vfc >> 4) & 0x0f) != 6) {
      npctxt->ignoredPacketTotalCount = npctxt->ignoredPacketTotalCount + 1;
      npctxt->ignoredOctetTotalCount = npctxt->ignoredOctetTotalCount + length;
      return; /* IP v6 only */
    }
    estimatedLen = sizeof(struct ip6_hdr)+htons(ipv6.ip6_plen);
    hlen = sizeof(struct ip6_hdr);
    ttl = ipv6.ip6_hops;
    
    src.ipVersion = 6, dst.ipVersion = 6;
    
    if(npctxt->ignoreIpAddresses) {
      memset(&src.ipType.ipv6, 0, sizeof(struct in6_addr));
      memset(&dst.ipType.ipv6, 0, sizeof(struct in6_addr));
    } else {
      memcpy(&src.ipType.ipv6, &ipv6.ip6_src, sizeof(struct in6_addr));
      memcpy(&dst.ipType.ipv6, &ipv6.ip6_dst, sizeof(struct in6_addr));
    }
    
    proto = ipv6.ip6_nxt; /* next header (protocol) */
    if (ipv6.ip6_nxt == 0) {
      proto = IPPROTO_IPV6;
    }
    break;
  case ETHERTYPE_VLAN: /* Courtesy of  Mikael Cam <mca@mgn.net> - 2002/08/28 */
  case DLT_NULL:
    estimatedLen = 0;
    hlen = 0;
    ttl = 0xFF;
    proto = 0;
    break;
  case ETHERTYPE_ARP:
  case ETHERTYPE_OSX_LOOPBACK_1: /* MacOSX loopback */
  case ETHERTYPE_OSX_LOOPBACK_6: /* MacOSX loopback */
  case ETHERTYPE_DEC_MOP:
  case ETHERTYPE_LOOPBACK:
    /* Ignore */
    return;
    break;
  default:
#ifdef DEBUG_IPFIX
    if(npctxt->traceMode && eth_type > ETHERTYPE_LEN_MAX)
      traceEvent(npctxt, TRACE_WARNING, "Unknown ethernet type: 0x%X (%d)",
		 eth_type, eth_type);
#endif
    /* Ignore */
    return;
  }
  
  plen = length-ehshift;
  if(caplen > estimatedLen) caplen = estimatedLen;
  offset = ehshift+hlen;
  
  
  /* Check for PIM Register encapsulated multicast messages. Unwrap. */
  if(proto == IPPROTO_PIM && plen >= (hlen+sizeof(struct _pim_register))) {
    struct _pim_register *pp = (struct _pim_register *)((char *)pkt + offset);
    
    /* If correct version, type is Register, and not a Null-Register */
    if(pp->pim_version == 2 && pp->pim_type == 1 && pp->N == 0) {	  
      /* Unwrap the IP packet placed in the payload  */
      struct ip *ip2;
      offset = offset + sizeof(struct _pim_register); /* Skip PIM */
      ip2 = (struct ip *)((u_int8_t *)pkt + offset);
      if(ip2->ip_v != 4 || offset > caplen) {
	/* Only handle IPv4 PIM payloads for now */
	npctxt->ignoredPacketTotalCount = npctxt->ignoredPacketTotalCount + 1;
	npctxt->ignoredOctetTotalCount = npctxt->ignoredOctetTotalCount + length;
	return;	    
      }
      
      memcpy(&ip, ip2, sizeof(struct ip));
      offset = offset + ip.ip_hl*4;
      proto = ip.ip_p;
      hlen = (u_int)ip.ip_hl * 4;
      off = ntohs(ip.ip_off);
      isFragment = (off & 0x3fff) ? 1 : 0;
      plen = plen - sizeof(struct _pim_register) - ip.ip_hl*4;
      if(npctxt->ignoreIpAddresses) {
	src.ipType.ipv4 = 0; /* 0.0.0.0 */
	dst.ipType.ipv4 = 0; /* 0.0.0.0 */
      } else {
	src.ipType.ipv4 = ntohl(ip.ip_src.s_addr);
	dst.ipType.ipv4 = ntohl(ip.ip_dst.s_addr);
      }
      
      is_pim = 1;
    }
  }

  switch(proto) {
  case IPPROTO_TCP:
    if(plen < (hlen+sizeof(struct tcphdr))) {
      npctxt->ignoredPacketTotalCount = npctxt->ignoredPacketTotalCount + 1;
      npctxt->ignoredOctetTotalCount = npctxt->ignoredOctetTotalCount + length;
      return; /* packet too short */
    }
    memcpy(&tp, (char *)pkt+offset, sizeof(struct tcphdr));
    if(npctxt->ignoreTcpUdpPorts)
      sport = dport = 0;
    else      
      sport = ntohs(tp.th_sport), dport = ntohs(tp.th_dport);
    tcpWindowSize = ntohs(tp.th_win);
    flags = tp.th_flags;
    seqnum = ntohl(tp.th_seq);
    if((tp.th_flags&TH_ACK)!=0)
      acknum = ntohl(tp.th_ack);
    off = tp.th_off * 4;

    if(plen >= (hlen+off)) {
      int pos = sizeof(struct tcphdr);

      while(pos < off) {
	u_int opt = *((u_char *)pkt + offset + pos);
	tcp_options = tcp_options | (1<<opt);
	if(opt == TCPOPT_EOL)
	  break;
	if(opt == TCPOPT_NOP)
	  pos++;
	else {
	  u_int len = *((u_char *)pkt + offset + pos + 1);
	  if(len == 0)
	    break;
	  if(opt == TCPOPT_WINDOW && len==3 && (flags&TH_SYN) != 0)
	    tcpWindowScale = *((u_char *)pkt + offset + pos + 2);	  
	  pos = pos + len;
	}
      }
    }


    payloadLen = caplen - offset - off;
    if(payloadLen > 0)
      payload = (unsigned char*)pkt+offset+off;
    else {
      payloadLen = 0;
      payload    = NULL;
    }

    if(npctxt->computeFingerprint
       && (eth_type == ETHERTYPE_IP) /* no IPv6 */) {
      int MSS=-1, WS=-1, S=0, N=0, D=0, T=0;
      char WSS[3], _MSS[5];
      struct tcphdr *tcp = (struct tcphdr *)((char *)pkt+offset);
      u_char *tcp_opt = (u_char *)(tcp + 1);
      u_char *tcp_data = (u_char *)((int)tcp + tp.th_off * 4);
      int tcpUdpLen = ntohs(ip.ip_len) - hlen;
      
      if(tp.th_flags & TH_SYN) {  /* only SYN or SYN-2ACK packets */
	if(tcpUdpLen > 0) {
	  if(ntohs(ip.ip_off) & IP_DF) D = 1;   /* don't fragment bit is set */
	  
	  if(tcp_data != tcp_opt) { /* there are some tcp_option to be parsed */
	    u_char *opt_ptr = tcp_opt;
	    
	    while(opt_ptr < tcp_data) {
	      switch(*opt_ptr) {
	      case TCPOPT_EOL:        /* end option: exit */
		opt_ptr = tcp_data;
		break;
	      case TCPOPT_NOP:
		N = 1;
		opt_ptr++;
		break;
	      case TCPOPT_SACKOK:
		S = 1;
		opt_ptr += 2;
		break;
	      case TCPOPT_MAXSEG:
		opt_ptr += 2;
		MSS = ntohs(ptohs(opt_ptr));
		opt_ptr += 2;
		break;
	      case TCPOPT_WSCALE:
		opt_ptr += 2;
		WS = *opt_ptr;
		opt_ptr++;
		break;
	      case TCPOPT_TIMESTAMP:
		T = 1;
		opt_ptr++;
		opt_ptr += (*opt_ptr - 1);
		break;
	      default:
		opt_ptr++;
		opt_ptr += (*opt_ptr - 1);
		break;
		  }
	    }
	  }
	  
	  if(WS == -1) sprintf(WSS, "WS");
	  else snprintf(WSS, sizeof(WSS), "%02d", WS);
	  
	  if(MSS == -1) sprintf(_MSS, "_MSS");
	  else snprintf(_MSS, sizeof(_MSS), "%04X", MSS);
	  
	  snprintf((char *)fingerprint, sizeof(fingerprint),
		   "%04X%s%02X%s%d%d%d%d%c%02X",
		   tcpWindowSize, _MSS, (int)ttlPredictor(ip.ip_ttl), WSS , S, N, D, T,
		   (tp.th_flags & TH_ACK) ? 'A' : 'S', tcpUdpLen);
	}
      }
    }
    break;
    
  case IPPROTO_UDP:
    if(plen < (hlen+sizeof(struct udphdr))) {
      npctxt->ignoredPacketTotalCount = npctxt->ignoredPacketTotalCount + 1;
      npctxt->ignoredOctetTotalCount = npctxt->ignoredOctetTotalCount + length;
      return; /* packet too short */
    }
    if(npctxt->ignoreTcpUdpPorts)
      sport = dport = 0;
    else
      sport = ntohs((*(struct udphdr *)((char *)pkt+offset)).uh_sport), 
      dport = ntohs((*(struct udphdr *)((char *)pkt+offset)).uh_dport);
    payloadLen = caplen - offset;
    if(payloadLen > 0)
      payload = (unsigned char*)((char *)pkt+offset+sizeof(struct udphdr));
    else {
      payloadLen = 0;
      payload    = NULL;
    }
    seqnum = 0;
    flags = 0;
    break;
  case IPPROTO_ICMP:
    if(plen < (hlen+sizeof(struct icmp))) {
      npctxt->ignoredPacketTotalCount = npctxt->ignoredPacketTotalCount + 1;
      npctxt->ignoredOctetTotalCount = npctxt->ignoredOctetTotalCount + length;
      return; /* packet too short */
    }
    payloadLen = caplen - offset;
    if(payloadLen > 0)
      payload = (unsigned char*)pkt+offset+sizeof(struct icmp);
    else {
      payloadLen = 0;
      payload    = NULL;
    }
    seqnum = 0;
    sport = dport = 0;
    icmp_type = ((struct icmp *)((char *)pkt+offset))->icmp_type;
    flags = 0;
    break;
  default:
    sport = dport = 0;
    payloadLen = 0;
    payload    = NULL;
    seqnum = 0;
    flags = 0;
    break;

  }
  
  /* ************************************************ */
  
  /* Is this is a fragment ?
     NOTE: IPv6 doesn't have the concept of fragments
  */
  if(isFragment) {
    u_short fragmentOffset = (off & 0x1FFF)*8, fragmentId = ntohs(ip.ip_id);
    IpV4Fragment *list = npctxt->fragmentsList, *prev = NULL;

    while(list != NULL) {
      if((list->src == src.ipType.ipv4)
	 && (list->dst == dst.ipType.ipv4)
	 && (list->fragmentId == fragmentId))
	break;
      else {
	/* Format of pkt_head->ts is 32 bit second, 32 bit fraction */
	if(((pkt_head->ts >> 32) - list->firstSeen) > 30 /* sec */) {
	  /* Purge expired fragment */
	  IpV4Fragment *next = list->next;
	  
	  if(prev == NULL)
	    npctxt->fragmentsList = next;
	  else
	    prev->next = next;
	  
	  free(list);
	  npctxt->fragmentListLen--;
	  list = next;
	} else {
	  prev = list;
	  list = list->next;
	}
      }
    }
    
    if(list == NULL) {
      /* Fragment not found */
      IpV4Fragment *frag = (IpV4Fragment*)malloc(sizeof(IpV4Fragment));
      
      /* We have enough memory */
      if(frag != NULL) {
	memset(frag, 0, sizeof(IpV4Fragment));
	frag->next = npctxt->fragmentsList;
	npctxt->fragmentsList = frag;
	frag->src = src.ipType.ipv4, frag->dst = dst.ipType.ipv4;
	frag->fragmentId = fragmentId;
	frag->firstSeen = pkt_head->ts >> 32;
	list = frag, prev = NULL;;
	npctxt->fragmentListLen++;
      }
    }
    
    if(list != NULL) {
      if(fragmentOffset == 0)
	list->sport = sport, list->dport = dport;
      
      list->len += plen, list->numPkts++;
      
      if(!(off & IP_MF)) {
	/* last fragment->we know the total data size */
	IpV4Fragment *next = list->next;
	sport = list->sport, dport = list->dport;
	plen = list->len, numPkts = list->numPkts;
	
	/* We can now free the fragment */
	if(prev == NULL)
	  npctxt->fragmentsList = next;
	else
	  prev->next = next;
	
	npctxt->fragmentListLen--;
	free(list);
      } else {
	/* More fragments: we'll handle the packet later */
	npctxt->ignoredPacketTotalCount = npctxt->ignoredPacketTotalCount + 1;
	npctxt->ignoredOctetTotalCount = npctxt->ignoredOctetTotalCount + length;
	return;
      }
    }
  }
  
  /* ************************************************ */
  
  if(npctxt->ignoreTcpUdpPorts || npctxt->ignoreIpAddresses) {
    payloadLen = 0;
    payload    = NULL;
  }
  
  addPktToHash(npctxt, proto, isFragment, numPkts, 
	       npctxt->ignoreTos ? 0 : ip.ip_tos,
	       src, sport, dst, dport, plen,
	       pkt_head->ts, pkt_head->ifindex, flags,
	       icmp_type,
	       npctxt->computeFingerprint ? fingerprint : NULL,
	       payload, payloadLen,
	       hlen,v4_options,tcp_options, ttl, seqnum, acknum,
	       is_pim, tcpWindowSize, tcpWindowScale);
}
