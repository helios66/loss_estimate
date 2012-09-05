#include <stdio.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <mapi.h>
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int fid;
	struct mapipkt *pkt;
	int packet_no, packet_ipv4_no, packet_ipv6_no, 
	    packet_mpls_no, packet_nonip_no;
	unsigned char *packet;
	unsigned char *p;
	int i, j ,ii=0;
	unsigned int l3_proto;
	// for error checking
	int err_no =0 , flag=0;
	char error[512];


	if(argc<2)
	{
		printf("\ntest_packet_read <device>\n");
		return -1;
	}
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if((fid=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((fid=mapi_apply_function(fd,"TO_BUFFER", 0))<0){
	  	fprintf(stderr, "Could not apply TO_BUFFER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	

	packet_no=packet_ipv4_no=packet_ipv6_no=packet_mpls_no=packet_nonip_no=0;
	
	while(ii++<20)
	{
		// sleep(5);
		if( (pkt=mapi_get_next_pkt(fd, fid)) != NULL)
		{
			packet=&(pkt->pkt);
			packet_no++;

			/* Check L3 protocol */
			p=packet;
			p+=12;
			l3_proto=((*p)<<8 | *(p+1)) & 0xFFFF;
			if (l3_proto==0x0800)
				packet_ipv4_no++;
			else if (l3_proto==0x86DD)
				packet_ipv6_no++;
			else if (l3_proto==0x8847)
				packet_mpls_no++;
			else
				packet_nonip_no++;

			if ((packet_no%1)==0)
				printf("packet_no: %d, packet_ipv4_no: %d, packet_ipv6_no: %d, packet_mpls_no: %d, packet_nonip_no: %d\n", packet_no, packet_ipv4_no, packet_ipv6_no, packet_mpls_no, packet_nonip_no);
				printf("ts: %llu, ifindex: %u, caplen: %u, wlen: %u\n", pkt->ts, pkt->ifindex, pkt->caplen, pkt->wlen);

				/* Print L3 protocol */
				if (l3_proto==0x0800)
					printf("L3 protocol: IPv4\n");
				else if (l3_proto==0x86DD)
					printf("L3 protocol: IPv6\n");
				else if (l3_proto==0x8847)
					printf("L3 protocol: MPLS\n");
				else
					printf("L3 protocol: non-IP (0x%04x)\n", l3_proto);

				/* Print Ethernet addresses */
    				p = packet;
    				p+=6;
    				printf("src Eth: ");
    				for (j = 0; j < 6; j++) {
      					printf("%02x", *p++);
      					if (((j+1)%2)==0)
       						printf(":");
    				}
				p = packet;
    				printf(" dst Eth: ");
    				for (j = 0; j < 6; j++) {
      					printf("%02x", *p++);
      					if (((j+1)%2)==0)
       						printf(":");
    				}
				printf("\n");

				/* Print IPv4 addresses */
				if (l3_proto==0x0800 || l3_proto==0x8847) {
    					p = packet;
    					p+=(ETH_HLEN+12);
					/* Skip 4-byte MPLS header */
					if (l3_proto==0x8847)
						p+=4;
    					printf("src IP: ");
    					for (j = 0; j < 4; j++) {
      						printf("%03d", *p++);
      						if (j<3)
        						printf(".");
    					}
    					printf(" dst IP: ");
    					for (j = 0; j < 4; j++) {
      						printf("%03d", *p++);
      						if (j<3)
        						printf(".");
      						else
        					printf("\n");
    					}
				}
				/* Print IPv6 addresses */
				else if (l3_proto==0x86DD) {
    					p = packet;
    					p+=(ETH_HLEN+8);
    					printf("src IP: ");
    					for (j = 0; j < 16; j++) {
      						printf("%02x", *p++);
      						if (((j+1)%2)==0)
        						printf(":");
    					}
    					printf(" dst IP: ");
    					for (j = 0; j < 16; j++) {
      						printf("%02x", *p++);
      						if (((j+1)%2)==0)
        						printf(":");
    					}
					printf("\n");
				}

				p=packet;
				for (i=0; i<40; i++) {
					printf("%02x", *p++);
					if (((i+1)%4)==0)
						printf(" ");
				}
				printf("\n");
		}
		else
		{
			fprintf(stderr, "Error mapi_read_pkt failed!\n");
			mapi_read_error( &err_no, error);
			fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
			return -1;
		}
	}
DOT;
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;


	printf("\nmapi_get_next_packet OK\n");
	
	/*
	 * Error checking starts
	 */
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	 if((pkt=mapi_get_next_pkt(0, fid)) == NULL){
	     mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6147){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	 }
DOT;	 
	 if((pkt=mapi_get_next_pkt(fd, 1234)) == NULL){
	 	mapi_read_error( &err_no, error);
		printf("Testing error case2: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6143){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	 }
DOT; 
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;
	/*
	 * Offline Tests
	 */

	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if((fid=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((fid=mapi_apply_function(fd,"TO_BUFFER", 0))<0){
	  	fprintf(stderr, "Could not apply TO_BUFFER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	/*
	 * Error checking starts
	 */
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	 if((pkt=mapi_get_next_pkt(0, fid)) == NULL){
	     mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6147){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	 }
DOT;	 
	 if((pkt=mapi_get_next_pkt(fd, 1234)) == NULL){
	 	mapi_read_error( &err_no, error);
		printf("Testing error case2: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6143){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	 }
DOT; 
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}


	if(!flag)
		printf("\nPacket read Error Checking OK\n");
	else 
		printf("\nPacket read Error Checking :FAILED:\n");

	return 0;
}
