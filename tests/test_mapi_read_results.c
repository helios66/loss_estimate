#include <stdio.h>
#include <unistd.h>
#include "mapi.h"
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int fid;
	mapi_results_t *cnt;
	int err_no =0 , flag=0;
	char error[512];

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

	if((fid=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
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
	sleep(3);
	
	if( (cnt = mapi_read_results(fd, fid))==NULL ){
		fprintf(stderr, "Mapi read results failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	/*
	 * Sanity check. Assuming that we have presence of network traffic
	 */
	if( *((int*)cnt->res)<=0)
		fprintf(stderr, "WARNING: No packets captured. Maybe no traffic on line..\n");
	else 
		printf("\nRead_results : %d\n", *((int*)cnt->res));
DOT;	
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	/*
	 * Error checking 
	 */
	fd = fid = 0;
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
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if(mapi_read_results(123,fid) ==NULL || mapi_read_results(fd,-1244655) ==NULL){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6145){
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

	if((fid=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
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
	
	if( (cnt = mapi_read_results(fd, fid))==NULL ){
		fprintf(stderr, "Mapi read results failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	/*
	 * Sanity check. Assuming that we have presence of network traffic
	 */

	sleep(10);
	if( *((int*)cnt->res)!=893)
		fprintf(stderr, "WARNING: No packets captured. Maybe no traffic on line.. %d\n" ,*((int*)cnt->res) );
	else 
		printf("\nRead_results : %d\n", *((int*)cnt->res));
DOT;	
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	/*
	 * Error checking 
	 */
	fd = fid = 0;
	if ((fd = mapi_create_offline_flow("./tracefile",MFF_PCAP))<0){
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
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if(mapi_read_results(123,fid) ==NULL || mapi_read_results(fd,-1244655) ==NULL){
		mapi_read_error( &err_no, error);
		printf("Testing error case2: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6145){
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
	printf("\nmapi_read_results OK\n");
	if(!flag)
		printf("\nMAPI read results Error Checking OK\n");
	else 
		printf("\nMAPI read results Error Checking :FAILED:\n");

return 0;
}
