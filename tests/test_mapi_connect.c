#include <stdio.h>
#include <unistd.h>
#include "mapi.h"
#include "test.h"

int main(int argc, char *argv[])
{
	int fd, fd2;
	int err;
	int fid_bpf2;
	int fid_cnt2;
	int fid_to_buffer;
	mapi_results_t *cnt;
	struct mapipkt *pkt;
	int err_no =0 , flag=0 , ret;
	char error[512];
	
	if(argc!=2)	{
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
	if((fid_to_buffer = mapi_apply_function(fd, "TO_BUFFER", 0))<0){
	  	fprintf(stderr, "Could not apply TO_BUFFER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;		
	if ((fd2 = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid_bpf2 = mapi_apply_function(fd2, "BPF_FILTER", "ip src net 195.113.0.0/16 and ip dst net 147.251.0.0/16"))<0){
	  	fprintf(stderr, "Could not apply BPF_FILTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((fid_cnt2 = mapi_apply_function(fd2, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	

	if((err=mapi_connect(fd))<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((err=mapi_connect(fd2))<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	

	if(err == 0)
	{
		printf("\nConnected\n");
	}
	else if(err == -2)
	{
		printf("\nauthorization error\n");
		return -1;
	}
	else if(err == -1)
	{
		printf("\nACK error\n");
		return -1;
	}
	else 
	{
		printf("\nerror at mapi_connect\n");
		return -1;
	}

	if ((pkt=mapi_get_next_pkt(fd, fid_to_buffer)) != NULL)
                  printf("Got packet\n");
      else
			printf("Error in mapi_get_next_packet\n");
                
      cnt = mapi_read_results(fd2, fid_cnt2);
DOT;
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if(mapi_close_flow(fd2)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	printf("\nmapi_connect OK\n");
	/*
	 * Error checking
	 */

	fd = 0;
	
	if( (ret = mapi_connect(13244)) == -1){
		mapi_read_error( &err_no, error);
		printf("\nTesting error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6145){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	fd = mapi_create_flow(argv[1]);
	
	if( (ret = mapi_connect(fd)) == -1){
		mapi_read_error( &err_no, error);
		printf("\nERROR: Errorcode :%d description: %s \n" ,err_no, error);
		flag=1;
	}
DOT;	
	if( (ret = mapi_connect(fd)) == -1){
		mapi_read_error( &err_no, error);
		printf("\nTesting error case2: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 3081){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;

/*
 * Offline testing
 */
	if ((fd = mapi_create_offline_flow("./tracefile", MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid_to_buffer = mapi_apply_function(fd, "TO_BUFFER", 0))<0){
	  	fprintf(stderr, "Could not apply TO_BUFFER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;		
	if ((fd2 = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid_bpf2 = mapi_apply_function(fd2, "BPF_FILTER", "ip src net 195.113.0.0/16 and ip dst net 147.251.0.0/16"))<0){
	  	fprintf(stderr, "Could not apply BPF_FILTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((fid_cnt2 = mapi_apply_function(fd2, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	

	if((err=mapi_connect(fd))<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((err=mapi_connect(fd2))<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	

	if(err == 0){
		printf("\nConnected\n");
	}
	else if(err == -2){
		printf("\nauthorization error\n");
		return -1;
	}
	else if(err == -1){
		printf("\nACK error\n");
		return -1;
	}
	else {
		printf("\nerror at mapi_connect\n");
		return -1;
	}

	if ((pkt=mapi_get_next_pkt(fd, fid_to_buffer)) != NULL)
                  printf("Got packet\n");
      else
			printf("Error in mapi_get_next_packet\n");
                
      cnt = mapi_read_results(fd2, fid_cnt2);
DOT;
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if(mapi_close_flow(fd2)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	printf("\nmapi_connect OK\n");
	/*
	 * Error checking
	 */

	fd = 0;
	
	if( (ret = mapi_connect(13244)) == -1){
		mapi_read_error( &err_no, error);
		printf("\nTesting error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6145){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP);
	
	if( (ret = mapi_connect(fd)) == -1){
		mapi_read_error( &err_no, error);
		printf("\nERROR: Errorcode :%d description: %s \n" ,err_no, error);
		flag=1;
	}
DOT;	
	if( (ret = mapi_connect(fd)) == -1){
		mapi_read_error( &err_no, error);
		printf("\nTesting error case2: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 3081){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;


	if(!flag)
		printf("\nMAPI Connect Error Checking OK\n");
	else 
		printf("\nMAPI Connect Error Checking :FAILED:\n");


	return 0;
}
