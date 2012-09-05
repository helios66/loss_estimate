#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include "anonymization.h"
#define CKSUM_CARRY(x) (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
#define IP2_HLEN(iph)	((iph)->ip_verhl & 0x0f)

unsigned int in_cksum(u_int16_t *addr, int len);

//thanks to libnet code
unsigned int in_cksum(u_int16_t *addr, int len)
{
    unsigned int sum;

    sum = 0;
	
    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1)
    {
        sum += *(u_int16_t *)addr;
    }

    return (sum);
}


#include <assert.h>

unsigned short calculate_tcp_sum(mapipacket *p) {
    unsigned int sum;
    int len;
    u_int16_t pad = 0;

    if (p->iph) {
	len = ntohs(p->iph->ip_len) - sizeof(IPHdr) - p->ip_options_len;
	sum = in_cksum((u_int16_t *)&p->iph->ip_src, 8); // src and dst
    } else if (p->ip6h) {
	//         IPv6 payload length - extension header length
	len = ntohs(p->ip6h->ip6_plen) - ((char *)p->tcph - (char *)(p->ip6h + 1));
	sum = in_cksum((u_int16_t *)&p->ip6h->ip6_src, 32); // src and dst
    } else {
	// Should never be here
	return 0;
    }
    
    p->tcph->th_sum = 0;
    sum += htons(IPPROTO_TCP + len);
    if (len % 2) {
	len--;
	*(unsigned char *)&pad = ((unsigned char *)p->tcph)[len]; // net order
	sum += pad;
    }
    sum += in_cksum((u_int16_t *)p->tcph, len);
    return (unsigned short)(CKSUM_CARRY(sum));
}

unsigned short calculate_ip_sum(mapipacket *p) {
    unsigned int sum;
    int ip_hl;
			
    p->iph->ip_csum = 0;
			
    ip_hl = IP2_HLEN(p->iph) << 2;
    sum = in_cksum((u_int16_t *)p->iph, ip_hl);
    return (unsigned short)(CKSUM_CARRY(sum));
}

unsigned short calculate_icmp_sum(mapipacket *p) {
			unsigned int sum;
			int len;
			u_int16_t pad = 0;
			
    if (p->iph) {
	p->icmph->csum = 0;
	sum = 0;
	len = ntohs(p->iph->ip_len)-sizeof(IPHdr)-p->ip_options_len;
	if (len % 2) {
	    len--;
	    *(unsigned char *)&pad = ((unsigned char *)p->icmph)[len]; // net order
	    sum += pad;
	}
	sum += in_cksum((u_int16_t *)p->icmph, len);
    } else if (p->ip6h) {
	p->icmp6h->icmp6_cksum = 0;
	sum = in_cksum((u_int16_t *)&p->ip6h->ip6_src, 32); // src and dst
	
	//         IPv6 payload length - extension header length
	len = ntohs(p->ip6h->ip6_plen) - ((char *)p->icmp6h - (char *)(p->ip6h + 1));
	sum += htons(IPPROTO_ICMPV6 + len);
	
	if (len % 2) {
	    len--;
	    *(unsigned char *)&pad = ((unsigned char *)p->icmp6h)[len]; // net order
	    sum += pad;
	}
	sum += in_cksum((u_int16_t *)p->icmp6h, len);
    } else {
	// Should never be here
	return 0;
    }
			
    return (unsigned short)(CKSUM_CARRY(sum));
}

unsigned short calculate_udp_sum(mapipacket *p) {
    unsigned int sum;
    int len;
    u_int16_t pad = 0;

    if (p->iph)
	sum = in_cksum((u_int16_t *)&p->iph->ip_src, 8); /* src and dst */
    else if (p->ip6h)
	sum = in_cksum((u_int16_t *)&p->ip6h->ip6_src, 32); /* src and dst */
    else
	return 0;
    
    p->udph->uh_chk = 0;
    sum += htons(IPPROTO_UDP);
    sum += p->udph->uh_len;
    
    len = ntohs(p->udph->uh_len);
    if (len % 2) {
	len--;
	*(unsigned char *)&pad = ((unsigned char *)p->udph)[len]; // net order
	sum += pad;
    }
    sum += in_cksum((u_int16_t *)p->udph, len);
    
    return (unsigned short)(CKSUM_CARRY(sum));
}
