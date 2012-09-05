#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <mapi.h>
#include "mapi/sample.h"
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int fid;
	int fidc1, fidc2;
	mapi_results_t *cnt1, *cnt2;
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
	if((fidc1=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if((fid = mapi_apply_function(fd, "SAMPLE", 20, PERIODIC))<0){
	  	fprintf(stderr, "SAMPLE could not be applied for flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if((fidc2=mapi_apply_function(fd, "PKT_COUNTER"))<0){
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
	/*
	 *  Sanity checks
	 */
	cnt1 = mapi_read_results(fd, fidc1);
	DOT;
	cnt2 = mapi_read_results(fd, fidc2);
	DOT;
	printf("Pkt: %d\tSample = %d\n", *((int*)cnt1->res), *((int*)cnt2->res));
	if(*((int*)cnt1->res)<= *((int*)cnt2->res)){
		  fprintf(stderr, "\nWARNING: Sample failed\n");
	}else
	printf("\nSAMPLE_PKTS OK\n");
DOT;	
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	

	/*
	 * Error cases check
	 */
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid = mapi_apply_function(fd, "SAMPLE", 1122320333, PERIODIC)) <0){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6145){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}	
	}
DOT;
	if((fid = mapi_apply_function(fd, "SAMPLE", 20, 1342)) <0){
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

	/*
	 * Offline tests
	 */

	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create offline flow using './tracefile'\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fidc1=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if((fid = mapi_apply_function(fd, "SAMPLE", 20, PERIODIC))<0){
	  	fprintf(stderr, "SAMPLE could not be applied for flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if((fidc2=mapi_apply_function(fd, "PKT_COUNTER"))<0){
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
	
	cnt1 = mapi_read_results(fd, fidc1);
	DOT;
	cnt2 = mapi_read_results(fd, fidc2);
	DOT;
	printf("Pkt: %d\tSample = %d\n", *((int*)cnt1->res), *((int*)cnt2->res));
	if(*((int*)cnt1->res)!=893 && *((int*)cnt2->res)!= 44){
		  fprintf(stderr, "\nWARNING: Sample failed\n");
	}else
		printf("\nSAMPLE_PKTS OK\n");
DOT;	
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	/*
	 * Error cases check
	 */
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create offline flow using './tracefile'\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if((fid = mapi_apply_function(fd, "SAMPLE", 1122320333, PERIODIC)) <0){
		mapi_read_error( &err_no, error);
		printf("Testing error case3: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6145){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}	
	}
DOT;
	if((fid = mapi_apply_function(fd, "SAMPLE", 20, 1342)) <0){
		mapi_read_error( &err_no, error);
		printf("Testing error case4: Errorcode :%d description: %s \n" ,err_no, error);
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

	if(!flag)
		printf("\nSample pkts Error Checking OK\n");
	else 
		printf("\nSample pkts Error Checking :FAILED:\n");
	
	return 0;
}
