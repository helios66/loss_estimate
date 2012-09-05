#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <ctype.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include "util.h"
#include "mapi.h"

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

void CreateTCPFlagString(struct tcphdr *tcph, char *flagBuffer);

void print_mapi_pkt(struct mapipkt *rec, int print_payload, int print_ifindex){

	unsigned char *p; 
	unsigned char *nextlayer;
	unsigned char *payload;
	int i=0, j=0;
	char abuf[17]; // for payload print
	char tcpFlags[9];
	char ipaddr[INET6_ADDRSTRLEN];
	
	struct ether_header *eth;
	uint16_t ethertype;
	struct iphdr *iph;
	struct ip6_hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct icmp *icmph;
	
	struct protoent *pt; //protocol name

	//printf("caplen: %u, wlen: %u\n", rec->caplen, rec->wlen);
	if (print_ifindex) {
		printf("if: %u\n", rec->ifindex);
	}

	p = &(rec->pkt);
	// lay the Ethernet header struct over the packet data
	eth = (struct ether_header *)p;

	// Datalink layer
	// TODO: timestamp info goes here..
	for(j=0; j<ETH_ALEN; j++) {
		printf("%X", eth->ether_shost[j]);
		if(j != 5) printf(":");
	}       
	printf(" > ");
	for(j=0; j<ETH_ALEN; j++){ 
		printf("%X", eth->ether_dhost[j]); 
		if(j != 5) printf(":");
	}

	ethertype = ntohs(eth->ether_type);
	printf(" type 0x%x ", ethertype);
	switch (ethertype) {
		case ETHERTYPE_IP: printf("IPv4\n"); break;
		case ETHERTYPE_IPV6: printf("IPv6\n"); break;
		case ETHERTYPE_ARP: printf("ARP\n"); break;
		case ETHERTYPE_REVARP: printf("Reverse ARP\n"); break;
		default: printf("\n"); break;
	}
	
	// skip ethernet header (14 bytes)
	nextlayer = (unsigned char *) (p + ETH_HLEN);

	// IPv4
	if (ethertype == ETHERTYPE_IP) {
		// lay the IP header struct over the packet data
		iph = (struct iphdr *)nextlayer;
		// skip IP header
		nextlayer += iph->ihl * 4;

		switch (iph->protocol) {
			case IPPROTO_TCP:
				// lay the TCP header struct over the packet data
				tcph = (struct tcphdr *)nextlayer;
				// skip TCP header
				nextlayer += tcph->doff * 4;

				printf("%s:%d > ", inet_ntoa(*(struct in_addr *)&(iph->saddr)), ntohs(tcph->source));
				printf("%s:%d", inet_ntoa(*(struct in_addr *)&(iph->daddr)), ntohs(tcph->dest));
				printf(" TCP TTL:%d TOS:0x%X ID:%d IpLen:%d DgmLen:%d\n",
					   iph->ttl, iph->tos, ntohs(iph->id),
					   iph->ihl << 2, ntohs(iph->tot_len));
				
				// print TCP flags
				CreateTCPFlagString(tcph, tcpFlags);
				printf("%s ", tcpFlags);
				// print other TCP info
				printf(" Seq: 0x%lX  Ack: 0x%lX  Win: 0x%X  TcpLen: %d\n",
					   (u_long) ntohl(tcph->seq), (u_long) ntohl(tcph->ack_seq),
					   ntohs(tcph->window), tcph->doff << 2);
				break;
			
			case IPPROTO_UDP:
				// lay the UDP header struct over the packet data
				udph = (struct udphdr *)nextlayer;
				// skip UDP header
				nextlayer = (unsigned char *) udph + UDP_HEADER_LEN;

				printf("%s:%d > ",   inet_ntoa(*(struct in_addr *)&(iph->saddr)), ntohs(udph->source));
				printf("%s:%d", inet_ntoa(*(struct in_addr *)&(iph->daddr)), ntohs(udph->dest));
				printf(" UDP TTL:%d TOS:0x%X ID:%d IpLen:%d DgmLen:%d\n",
					   iph->ttl, iph->tos, ntohs(iph->id),
					   iph->ihl << 2, ntohs(iph->tot_len));
				printf("Len: %d\n", ntohs(udph->len) - UDP_HEADER_LEN);
				break;
			
			case IPPROTO_ICMP:
				// lay the ICMP header struct over the packet data
				icmph = (struct icmp *)nextlayer;
				nextlayer = (unsigned char *) icmph + 8;

				printf("%s > ", inet_ntoa(*(struct in_addr *)&(iph->saddr)));
				printf("%s", inet_ntoa(*(struct in_addr *)&(iph->daddr)));
				printf(" ICMP TTL:%d TOS:0x%X ID:%d IpLen:%d DgmLen:%d\n",
					   iph->ttl, iph->tos, ntohs(iph->id),
					   iph->ihl << 2, ntohs(iph->tot_len));
				printf("Type: %d  Code: %d  ", icmph->icmp_type, icmph->icmp_code);

				switch(icmph->icmp_type){
					
					case ICMP_ECHOREPLY:
						printf("ID: %d  Seq: %d  ECHO REPLY", 
							   ntohs(icmph->icmp_id), ntohs(icmph->icmp_seq));
						break;

					case ICMP_DEST_UNREACH:
						printf("DESTINATION UNREACHABLE: ");
						switch(icmph->icmp_code){
							
							case ICMP_NET_UNREACH:
								printf("NET UNREACHABLE");
								break;

							case ICMP_HOST_UNREACH:
								printf("HOST UNREACHABLE");
								break;

							case ICMP_PROT_UNREACH:
								printf("PROTOCOL UNREACHABLE");
								break;

							case ICMP_PORT_UNREACH:
								printf("PORT UNREACHABLE");
								break;

							case ICMP_FRAG_NEEDED:
								printf("FRAGMENTATION NEEDED, DF SET\n"
										"NEXT LINK MTU: %u",
										ntohs(icmph->icmp_nextmtu));
								break;

							case ICMP_SR_FAILED:
								printf("SOURCE ROUTE FAILED");
								break;

							case ICMP_NET_UNKNOWN:
								printf("NET UNKNOWN");
								break;

							case ICMP_HOST_UNKNOWN:
								printf("HOST UNKNOWN");
								break;

							case ICMP_HOST_ISOLATED:
								printf("HOST ISOLATED");
								break;

							case ICMP_PKT_FILTERED_NET:
								printf("ADMINISTRATIVELY PROHIBITED NETWORK FILTERED");
								break;

							case ICMP_PKT_FILTERED_HOST:
								printf("ADMINISTRATIVELY PROHIBITED HOST FILTERED");
								break;

							case ICMP_NET_UNR_TOS:
								printf("NET UNREACHABLE FOR TOS");
								break;

							case ICMP_HOST_UNR_TOS:
								printf("HOST UNREACHABLE FOR TOS");
								break;

							case ICMP_PKT_FILTERED:
								printf("ADMINISTRATIVELY PROHIBITED,\nPACKET FILTERED");
								break;

							case ICMP_PREC_VIOLATION:
								printf("PREC VIOLATION");
								break;

							case ICMP_PREC_CUTOFF:
								printf("PREC CUTOFF");
								break;

							default:
								printf("UNKNOWN");
								break;
						}
						break;

					case ICMP_SOURCE_QUENCH:
						printf("SOURCE QUENCH");
						break;

					case ICMP_REDIRECT:
						printf("REDIRECT");
						switch(icmph->icmp_code)
						{
							case ICMP_REDIR_NET:
								printf(" NET");
								break;

							case ICMP_REDIR_HOST:
								printf(" HOST");
								break;

							case ICMP_REDIR_TOS_NET:
								printf(" TOS NET");
								break;

							case ICMP_REDIR_TOS_HOST:
								printf(" TOS HOST");
								break;
						}
						break;

					case ICMP_ECHO:
						printf("ID: %d  Seq: %d  ECHO",
							   ntohs(icmph->icmp_id), ntohs(icmph->icmp_seq));
						break;

					case ICMP_ROUTER_ADVERTISE:
						printf("ROUTER ADVERTISMENT: "
								"Num addrs: %d Addr entry size: %d Lifetime: %u", 
								icmph->icmp_num_addrs, icmph->icmp_wpa, 
								icmph->icmp_lifetime);
						break;

					case ICMP_ROUTER_SOLICIT:
						printf("ROUTER SOLICITATION");
						break;

					case ICMP_TIME_EXCEEDED:
						printf("TTL EXCEEDED");
						switch(icmph->icmp_code)
						{
							case ICMP_TIMEOUT_TRANSIT:
								printf(" IN TRANSIT");
								break;

							case ICMP_TIMEOUT_REASSY:
								printf(" TIME EXCEEDED IN FRAG REASSEMBLY");
								break;
						}
						break;

					case ICMP_PARAMETERPROB:
						printf("PARAMETER PROBLEM");
						switch(icmph->icmp_code)
						{
							case ICMP_PARAM_BADIPHDR:
								printf(": BAD IP HEADER BYTE %u", icmph->icmp_pptr);
								break;

							case ICMP_PARAM_OPTMISSING:
								printf(": OPTION MISSING");
								break;

							case ICMP_PARAM_BAD_LENGTH:
								printf(": BAD LENGTH");
								break;
						}
						break;

					case ICMP_TIMESTAMP:
						printf("ID: %u  Seq: %u  TIMESTAMP REQUEST", 
								ntohs(icmph->icmp_id), ntohs(icmph->icmp_seq));
						break;

					case ICMP_TIMESTAMPREPLY:
						printf("ID: %u  Seq: %u  TIMESTAMP REPLY:\n"
								"Orig: %u Rtime: %u  Ttime: %u", 
								ntohs(icmph->icmp_id), ntohs(icmph->icmp_seq),
								icmph->icmp_otime, icmph->icmp_rtime, 
								icmph->icmp_ttime);
						break;

					case ICMP_INFO_REQUEST:
						printf("ID: %u  Seq: %u  INFO REQUEST", 
								ntohs(icmph->icmp_id), ntohs(icmph->icmp_seq));
						break;

					case ICMP_INFO_REPLY:
						printf("ID: %u  Seq: %u  INFO REPLY", 
								ntohs(icmph->icmp_id), ntohs(icmph->icmp_seq));
						break;

					case ICMP_ADDRESS:
						printf("ID: %u  Seq: %u  ADDRESS REQUEST", 
								ntohs(icmph->icmp_id), ntohs(icmph->icmp_seq));
						break;

					case ICMP_ADDRESSREPLY:
						printf("ID: %u  Seq: %u  ADDRESS REPLY: 0x%08X", 
								ntohs(icmph->icmp_id), ntohs(icmph->icmp_seq),
								(u_int) icmph->icmp_mask); 
						break;

					default:
						printf("UNKNOWN");
						break;
				}
				printf("\n");
				break;
				
			default:
				printf("%s > ", inet_ntoa(*(struct in_addr *)&(iph->saddr)));
				printf("%s", inet_ntoa(*(struct in_addr *)&(iph->daddr)));
				pt = getprotobynumber(iph->protocol);	// get protocol name
				printf(" %s TTL:%d TOS:0x%X ID:%d IpLen:%d DgmLen:%d\n",
					   pt->p_name, iph->ttl, iph->tos, ntohs(iph->id),
					   iph->ihl << 2, ntohs(iph->tot_len));
				break;
		}
	}
	
	//IPv6
	else if (ethertype == ETHERTYPE_IPV6) {
		// lay the IP header struct over the packet data
		ip6h = (struct ip6_hdr *)nextlayer;

		//TODO: Add TCP/UDP/ICMP6 Parsing
		//	Make sure ntohs() applied correctly
		//	Make sure parsing of header fields is correct
		//	Add printing of header fields version and flow label
		//	Add support for option fields
		//	Calculate header length and total length
		//	Add header length to nextlayer so we print only payload

		//processing logic goes here

		printf("%s > ", inet_ntop(AF_INET6, (struct in6_addr *)&(ip6h->ip6_src), ipaddr, sizeof(ipaddr)));
		printf("%s", inet_ntop(AF_INET6, (struct in6_addr *)&(ip6h->ip6_dst), ipaddr, sizeof(ipaddr)));
		pt = getprotobynumber(ip6h->ip6_nxt);	// get protocol name
		printf(" %s HopLim:%d TC:%d PayloadLen:%d\n",
			   pt->p_name, ip6h->ip6_hlim,
			   ((ip6h->ip6_flow >> 20) & 0xFF), ntohs(ip6h->ip6_plen));
	}

	// Payload
	if((nextlayer != NULL) && print_payload){
		payload = nextlayer;
		memset(abuf, 0, 17);
		for( i=0; (unsigned int)payload < (unsigned int)(&rec->pkt)+(rec->caplen); payload++, i++) {
			abuf[i%16] = isprint(*payload&0xff) ? (*payload&0xff) : '.';
			printf("%02x ", *payload&0xff);
			if ((i%16)==15) {
				printf("        %s\n", abuf);
				memset(abuf, 0, 17);
			}
		}
		if((i > 0) && (i%16 != 16)){
			while(i%16) {
				printf("   ");
				i++;
			}
			printf("        %s\n", abuf);
		}
	}
	printf("\n");
}

void create_pkt(Packet* pkt, struct mapipkt *rec)
{
	unsigned char *p; 
	unsigned char *nextlayer;
/*	unsigned char *payload;
	int i=0, j=0;
	char abuf[17]; // for payload print
	char tcpFlags[9];*/

	//printf("caplen: %u, wlen: %u\n", rec->caplen, rec->wlen);
	pkt->caplen = rec->caplen;

	p = pkt->pkt = &(rec->pkt);
	// lay the Ethernet header struct over the packet data
	pkt->eth = (struct ether_header *)p;

	// Datalink layer
	pkt->ethertype = ntohs(pkt->eth->ether_type);
	
	// skip ethernet header (14 bytes)
	nextlayer = (unsigned char *) (p + ETH_HLEN);

	// IP
	if (pkt->ethertype == ETHERTYPE_IP)
	{
		// lay the IP header struct over the packet data
		pkt->iph = (struct iphdr *)nextlayer;
		// skip IP header
		nextlayer += pkt->iph->ihl * 4;

		switch (pkt->iph->protocol)
		{
			case IPPROTO_TCP:
				// lay the TCP header struct over the packet data
				pkt->tcph = (struct tcphdr *)nextlayer;
				// skip TCP header
				nextlayer += pkt->tcph->doff * 4;
				break;

			case IPPROTO_UDP:
				// lay the UDP header struct over the packet data
				pkt->udph = (struct udphdr *)nextlayer;
				// skip UDP header
				nextlayer = (unsigned char *) pkt->udph + UDP_HEADER_LEN;
				break;

			case IPPROTO_ICMP:
				// lay the ICMP header struct over the packet data
				pkt->icmph = (struct icmp *)nextlayer;
				nextlayer = (unsigned char *) pkt->icmph + 8;
				break;
				
			default:
				pkt->pt = getprotobynumber(pkt->iph->protocol);	// get protocol name
				break;
		}
	}

	// Payload
	if (nextlayer != NULL)
		pkt->payload = nextlayer;
	//pkt->payload_size = ntohs(pkt->iph->tot_len) - (pkt->iph->ihl * 4) - (pkt->tcph->doff * 4);
	pkt->payload_size = (unsigned int)(&rec->pkt)+(rec->caplen) - (unsigned int)pkt->payload;
}

void CreateTCPFlagString(struct tcphdr *tcph, char *flagBuffer){
    // parse TCP flags
	*flagBuffer++ = (char) ((tcph->res1) ? '1' : '*');
	*flagBuffer++ = (char) ((tcph->res2) ? '2' : '*');
    *flagBuffer++ = (char) ((tcph->urg)  ? 'U' : '*');
    *flagBuffer++ = (char) ((tcph->ack)  ? 'A' : '*');
    *flagBuffer++ = (char) ((tcph->psh)  ? 'P' : '*');
    *flagBuffer++ = (char) ((tcph->rst)  ? 'R' : '*');
    *flagBuffer++ = (char) ((tcph->syn)  ? 'S' : '*');
    *flagBuffer++ = (char) ((tcph->fin)  ? 'F' : '*');
    *flagBuffer = '\0';
}

