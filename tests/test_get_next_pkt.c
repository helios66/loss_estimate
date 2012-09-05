#include <stdio.h>
#include <unistd.h>
#include <mapi.h>
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int fid;
	struct mapipkt *pkt;
	int err_no =0 , flag=0;
	char error[512];
	int i;
	
	if(argc!=2)
	{
		printf("\nWrong arguments\n");
		return -1;
	}
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid=mapi_apply_function(fd, "TO_BUFFER", 0))<0){
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
 * Sanity check
 */
	if((pkt=mapi_get_next_pkt(fd, fid)) != NULL){
		printf("Got packet\n");
	}
	else{
		printf("\nError in mapi_get_next_packet\n");
	}


	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;
	/* non-blocking buffer test */
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid=mapi_apply_function(fd, "TO_BUFFER", NOWAIT))<0){
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
 * Sanity check
 */
	for (i=0; i < 50; i++) {
		if((pkt=mapi_get_next_pkt(fd, fid)) != NULL){
			printf("Got packet\n");
		}
		else {
			printf("No packet\n");
		}
	}

DOT;

	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	printf("\nmapi_get_next_packet OK\n");
	
	/*
 	 * Error reporting checking 
 	 */
	fd =0;
	if(mapi_get_next_pkt(fd , fid) == NULL){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6147){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}

	}
DOT;	
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if(mapi_get_next_pkt(fd , fid) == NULL){
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
	 * Offline tests
	 */
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid=mapi_apply_function(fd, "TO_BUFFER", WAIT))<0){
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
 * Sanity check
 */
	if((pkt=mapi_get_next_pkt(fd, fid)) != NULL){
		  if(pkt->caplen!=60)
			    fprintf(stderr, "WARNING:sanity check failed packet size not the expected one %d\n" , pkt->caplen);
	}else 
		fprintf(stderr, "WARNING:sanity check failed NULL packet returned\n");
DOT;	
	/*
 	 * Error reporting checking 
 	 */
	if(mapi_get_next_pkt(-12 , fid) == NULL){
		mapi_read_error( &err_no, error);
		printf("Testing error case3: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6147){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;	
	if(mapi_get_next_pkt(fd , -1234) == NULL){
		mapi_read_error( &err_no, error);
		printf("Testing error case4: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6147){
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


	if(!flag)
		printf("\nGet Next Packet Error Checking OK\n");
	else 
		printf("\nGet Next Packet Error Checking :FAILED:\n");
	
	return 0;
}
