/****************************************************
 *
 *	Testing REGEXP - Extra MAPI Function Library
 *
 ***************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <mapi.h>
#include "../test.h"

int main(int argc, char *argv[]){

	int fd;
	int fid, fidc, fids;
	mapi_results_t *cntc, *cnts;
	int err_no =0, flag=0;
	char error[512];
	mapi_flow_info_t info;

	if(argc != 2){
		printf("Usage: %s <interface> \n", argv[0]);
		return -1;
	}
	
	if( (fd = mapi_create_flow(argv[1])) < 0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	if( (fidc = mapi_apply_function(fd, "PKT_COUNTER")) < 0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;	
	if( (fid = mapi_apply_function(fd, "REGEXP", "HTTP.*OK")) < 0){
	  	fprintf(stderr, "Could not apply REGEXP to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;	
	if( (fids = mapi_apply_function(fd, "PKT_COUNTER")) < 0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;			
	if(mapi_connect(fd) < 0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;

/*
 * Sanity checks
 */
	sleep(5);
	cntc = mapi_read_results(fd, fidc);
DOT;	
	cnts = mapi_read_results(fd, fids);
DOT;	
	printf("\n\nPackets read: %d\t Packets matched : %d", *((int*)cntc->res), *((int*)cnts->res));

	if (*((int*)cntc->res) <= *((int*)cnts->res))
		fprintf(stderr,"\nWARNING: REGXEP failed\n");
	else
		printf("\nREGEXP OK\n\n");
	
	if(mapi_close_flow(fd) < 0){
		fprintf(stderr, "Close flow failed\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;

/*
 *Error Checking 
 */
	if ( (fd = mapi_create_flow(argv[1])) < 0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	if( (fid = mapi_apply_function(fd, "REGEXP", "*)!@#@!##############@$#@@@@@@@@@@@@@@@@^^^^^^^^^^^^^^^^^^^#$$^^^^^^^^^^^^ \
							$#!!!!!!!!!!!!!!!!!!!!!!#$^^^^^^^^^^^^^^%%%%%%%%&&&&&&&&&&&&&&%%%%%%%%%%%%%% \
							*&&&&&&&&&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%^^^^^^^^^^^^^^^ \
							@@@@@@@@@@@@@")) < 0){		/* invalid pattern - nothing to repeat */
		mapi_read_error(&err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n", err_no, error);
		if(err_no != 7000){
			printf("\t\tWrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if( (fid = mapi_apply_function(fd, "REGEXP", ")(")) < 0){			/* invalid pattern - unmatched parentheses */
		mapi_read_error(&err_no, error);
		printf("Testing error case2: Errorcode :%d description: %s \n", err_no, error);
		if(err_no != 7000){
			printf("\t\tWrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if(mapi_close_flow(fd) < 0){
		fprintf(stderr, "Close flow failed\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}

/*
 * Offline checking
 */
	if ( (fd = mapi_create_offline_flow("../tracefile", MFF_PCAP)) < 0){
		fprintf(stderr, "Could not create offline flow using tracefile\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	if( (fidc = mapi_apply_function(fd, "PKT_COUNTER")) < 0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;	
	if( (fid = mapi_apply_function(fd,"REGEXP", "HTTP.*OK")) < 0){
	  	fprintf(stderr, "Could not apply REGEXP to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;	
	if( (fids = mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}

DOT;			
	if(mapi_connect(fd) < 0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;

/*
 * Sanity checks
 */
	do{
		sleep(1);
		mapi_get_flow_info(fd, &info);
	} while(info.status != FLOW_FINISHED);

	cntc = mapi_read_results(fd, fidc);
DOT;	
	cnts = mapi_read_results(fd, fids);
DOT;	
	printf("\n\nPackets read: %d\t Packets matched : %d", *((int*)cntc->res), *((int*)cnts->res));

	if (*((int*)cntc->res) != 893 && *((int*)cnts->res) != 4)
		fprintf(stderr,"\nWARNING: REGXEP failed\n");
	else
		printf("\nOffline REGEXP OK\n\n");
	
	if(mapi_close_flow(fd) < 0){
		fprintf(stderr, "Close flow failed\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;

/*
 *Error Checking 
 */
	if ( (fd = mapi_create_offline_flow("../tracefile", MFF_PCAP))<0){
		fprintf(stderr, "Could not create offline flow using tracefile\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	if( (fid = mapi_apply_function(fd, "REGEXP", "*)!@#@!##############@$#@@@@@@@@@@@@@@@@^^^^^^^^^^^^^^^^^^^#$$^^^^^^^^^^^^ \
							$#!!!!!!!!!!!!!!!!!!!!!!#$^^^^^^^^^^^^^^%%%%%%%%&&&&&&&&&&&&&&%%%%%%%%%%%%%% \
							*&&&&&&&&&&&&&&&&&&&&&&&&&&&@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%^^^^^^^^^^^^^^^ \
							@@@@@@@@@@@@@")) < 0){		/* invalid pattern - nothing to repeat */		
		mapi_read_error(&err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n", err_no, error);
		if(err_no != 7000){
			printf("\t\tWrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if( (fid = mapi_apply_function(fd, "REGEXP", ")(")) < 0){			/* invalid pattern - unmatched parentheses */
		mapi_read_error(&err_no, error);
		printf("Testing error case2: Errorcode :%d description: %s \n", err_no, error);
		if(err_no != 7000){
			printf("\t\tWrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;
	if(mapi_close_flow(fd) < 0){
		fprintf(stderr, "Close flow failed\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
	
	if(!flag)
		printf("\nRegexp Error Checking OK\n\n");
	else 
		printf("\nRegexp Flow Error Checking :FAILED:\n\n");
	
	return 0;
}
