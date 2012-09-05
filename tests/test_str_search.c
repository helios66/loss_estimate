/*******************************************
 *
 *	test STR_SEARCH
 *
 ******************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <mapi.h>
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int fid;
	int fidc, fids;
	mapi_results_t *cntc, *cnts;
	int err_no =0 , flag=0;
	char error[512];
	
	if(argc!=2){
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

	if((fidc=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((fid=mapi_apply_function(fd, "STR_SEARCH", "www", 0, 1500))<0){
	  	fprintf(stderr, "Could not apply STR_SEARCH to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((fids=mapi_apply_function(fd, "PKT_COUNTER"))<0){
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
	 * Sanity checks
	 */
	sleep(5);
	cntc = mapi_read_results(fd,fidc);
DOT;	
	cnts = mapi_read_results(fd,fids);
DOT;	
	printf("\nPackets read: %d\t Packets matched : %d", *((int*)cntc->res), *((int*)cnts->res));
	if (*((int*)cntc->res) <= *((int*)cnts->res)){
		  fprintf(stderr,"\nWARNING: STR_SEARCH failed\n");	
	}
	else
		printf("\nSTR_SEARCH OK\n");
	
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;
	/*
	 *Error Checking 
	 */
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if( (fid = mapi_apply_function(fd, "STR_SEARCH" , "TEST" ,-120 , 1500))<0 ){
		  mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7002){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if( (fid = mapi_apply_function(fd, "STR_SEARCH" , "TEST" ,0 , 23412))<0 ){
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
	 * Offline checking
	 */
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create offline flow using './tracefile'\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if((fidc=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if((fid=mapi_apply_function(fd, "STR_SEARCH", "www", 0, 1500))<0){
	  	fprintf(stderr, "Could not apply STR_SEARCH to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;	
	if((fids=mapi_apply_function(fd, "PKT_COUNTER"))<0){
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
	 * Sanity checks
	 */
	sleep(5);
	cntc = mapi_read_results(fd,fidc);
DOT;	
	cnts = mapi_read_results(fd,fids);
DOT;	
	printf("\nPackets read: %d\t Packets matched : %d", *((int*)cntc->res), *((int*)cnts->res));
	if (*((int*)cntc->res)!=893 && *((int*)cnts->res)!=2){
		  fprintf(stderr,"\nWARNING: STR_SEARCH failed\n");	
	}
	else
		printf("\nSTR_SEARCH OK\n");
	
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;
	/*
	 *Error Checking 
	 */
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create offline flow using './tracefile'\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if( (fid = mapi_apply_function(fd, "STR_SEARCH" , "TEST" ,-120 , 1500))<0 ){
		  mapi_read_error( &err_no, error);
		printf("Testing error case3: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7002){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if( (fid = mapi_apply_function(fd, "STR_SEARCH" , "TEST" ,0 , 23412))<0 ){
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
		printf("\nSTR_SEARCH Error Checking OK\n");
	else 
		printf("\nSTR_SEARCH Error Checking :FAILED:\n");
	
return 0;
}
	
