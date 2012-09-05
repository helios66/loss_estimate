#include "util.h"

char *get_tcp_payload(struct mapipkt *pkt, int *size)
{
	unsigned char *p;
	unsigned char *payload;
	
	struct ether_header *ep;
	struct iphdr *iph;
	struct tcphdr *tcph;

	//  Ethernet packet
	p = &pkt->pkt;

	// lay the Ethernet header struct over the packet data
	ep = (struct ether_header *)p;
	
	// skip ethernet header

	p += sizeof(struct ether_header);

	// IP header struct over the packet data

	iph = (struct iphdr *)p;

	//p += sizeof(struct iphdr) + (iph->ihl * 4) ;
	p += iph->ihl * 4;
	payload  = (unsigned char *) (p + (iph->ihl*4));
	
	// TCP header over packet data
	tcph = (struct tcphdr *)p;
	payload = (unsigned char *)(p + (iph->ihl * 4) + (tcph->doff *4));
	//p += sizeof(struct tcphdr) + (tcph->doff * 4);
    p += tcph->doff *4;
  
	*size = pkt->caplen - sizeof(struct ether_header) - (iph->ihl * 4) - (tcph->doff * 4);

	return p;
}

char *segment_as_string(unsigned char *segment,short size,char delim_start,char delim_end) 
{
		void *start,*end;
		char *info;
		short len;

		start = (void *)memchr((void *)segment,delim_start,size);
		end   = (void *)memchr((void *)segment,delim_end,size);

		if(!start || !end) {
			printf("Malformed PSV response\n");
			return NULL;
		}
		
		start+=1;
		len=(short)(end-start);

		info=(char *)malloc((len+1)*sizeof(char));
		info[len]='\0';
		memcpy(info,start,len);

		return info;
}


count_results *count_results_init()
{
	count_results *temp;

	temp = (count_results *)malloc(sizeof(count_results));

	temp->fd = 0;
	temp->pkt_counter = 0;
	temp->byte_counter = 0;
	temp->bytes =  0; 
	temp->pkts = 0; 
	temp->filter = 0;
	temp->filterc = 0;
	temp->open = 1;

	temp->filt = NULL;
	temp->next = NULL;

	return temp;
}

void count_results_append(count_results **head, count_results *add)
{
	count_results *temp;
	
	if(add == NULL)
	{
		printf("\nadd == NULL \n");

		return;
	}
	if(*head == NULL)
	{
		*head = add;
	}
	else
	{
		for(temp = *head; temp->next != NULL; temp = temp->next)
			;

		temp->next = add;
	}

	return;
}
	
