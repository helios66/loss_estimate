/*************************************************
 *
 *	Testing TOP - Extra MAPI Function Library
 *
 ************************************************/

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include "mapi.h"
#include "mapi/topx.h"
#include "../test.h"

void terminate();
int fd;
int err_no = 0;
char error[512];

int main(int argc, char *argv[]){

	int fid;
	int flag = 0;
	unsigned int i;
	mapi_results_t *cnt;
	struct topx_result *tmp;

	signal(SIGINT, terminate);
	signal(SIGQUIT, terminate);
	signal(SIGTERM, terminate);

	if(argc != 2){
		printf("Usage: %s <interface> \n", argv[0]);
		return -1;
	}
/*
 * Offline tests
 */
	if( (fd = mapi_create_offline_flow("../tracefile", MFF_PCAP)) < 0){
		fprintf(stderr, "Could not create flow using tracefile\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	if( (fid = mapi_apply_function(fd, "TOP", 10, TOPX_TCP, TOPX_TCP_DSTPORT)) == -1){
		fprintf(stderr, "Could not apply function TOP to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	if(mapi_connect(fd) < 0){
		fprintf(stderr, "Could not connect to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	sleep(2);
	cnt = mapi_read_results(fd, fid);
	printf("\nresults: %d\n", *((int*)cnt->res));
	tmp = (struct topx_result *)(((int*)cnt->res) + 1);
		
	for(i = 0; i < (*((unsigned int*)cnt->res)); i++){

		printf("\n\tPort: %u ", tmp->value);
		printf("\n\tPackets: %u ", tmp->count);
		printf("\n\tBytes: %llu\n", tmp->bytecount);
		tmp++;
	}
DOT;
	if(mapi_close_flow(fd) < 0){
		fprintf(stderr, "Close flow failed\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
/*
 * Offline error checking
 */
	fd = fid = 0;
	
	if( (fd = mapi_create_offline_flow("../tracefile", MFF_PCAP)) < 0){
		fprintf(stderr, "Could not create flow using tracefile\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	if( (fid = mapi_apply_function(fd, "TOP", 1001, TOPX_TCP, TOPX_TCP_DSTPORT)) == -1){	// maximum value of first argument is 1000
		mapi_read_error(&err_no, error);
		printf("\nTesting error case1: Errorcode :%d description: %s \n", err_no, error);
		if(err_no != 7001){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode\n");
			flag = 1;
		}
	}
DOT;
	if( (fid = mapi_apply_function(fd, "TOP", 10, 4, TOPX_TCP_DSTPORT)) == -1){		// protocol: TOPX_IP = 1, TOPX_TCP = 2, TOPX_UDP = 3
		mapi_read_error(&err_no, error);
		printf("Testing error case2: Errorcode :%d description: %s \n", err_no, error);
		if(err_no != 7002){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode\n");
			flag = 1;
		}
	}
DOT;
	if( (fid = mapi_apply_function(fd, "TOP", 10, TOPX_IP, TOPX_TCP_DSTPORT)) == -1){	// different protocol and field
		mapi_read_error(&err_no, error);
		printf("Testing error case3: Errorcode :%d description: %s \n", err_no, error);
		if(err_no != 7003){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode\n");
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
DOT;
	if (!flag)
		printf("\n\nTOP Offline Error Checking OK\n\n");
	else{
		fprintf(stderr,"\n\nTOP Offline Error Checking :FAILED:\n\n");
		exit(EXIT_FAILURE);
	}

	fd = fid = flag = 0;

/*
 * Online error checking
 */
	if ((fd = mapi_create_flow(argv[1])) < 0) {
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	if( (fid = mapi_apply_function(fd, "TOP", 1001, TOPX_TCP, TOPX_TCP_DSTPORT)) == -1){	// maximum value of first argument is 1000
		mapi_read_error(&err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n", err_no, error);
		if(err_no != 7001){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode\n");
			flag = 1;
		}
	}
DOT;
	if( (fid = mapi_apply_function(fd, "TOP", 10, 4, TOPX_TCP_DSTPORT)) == -1){		// protocol: TOPX_IP = 1, TOPX_TCP = 2, TOPX_UDP = 3
		mapi_read_error(&err_no, error);
		printf("Testing error case2: Errorcode :%d description: %s \n", err_no, error);
		if(err_no != 7002){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode\n");
			flag = 1;
		}
	}
DOT;
	if( (fid = mapi_apply_function(fd, "TOP", 10, TOPX_IP, TOPX_TCP_DSTPORT)) == -1){	// different protocol and field
		mapi_read_error(&err_no, error);
		printf("Testing error case3: Errorcode :%d description: %s \n", err_no, error);
		if(err_no != 7003){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode\n");
			flag = 1;
		}
	}
DOT;
	if(mapi_close_flow(fd) < 0){
		fprintf(stderr, "Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if (!flag)
		printf("\n\nTOP Error Checking OK\n\n");
	else{
		fprintf(stderr,"\n\nTOP Error Checking :FAILED:\n\n");
		exit(EXIT_FAILURE);
	}
DOT;
	fd = fid = 0;

/*
 * Online tests
 */
	if( (fd = mapi_create_flow(argv[1])) < 0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	if( (fid = mapi_apply_function(fd, "TOP", 10, TOPX_TCP, TOPX_TCP_DSTPORT)) == -1){
		fprintf(stderr, "Could not apply function TOP to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	if(mapi_connect(fd) < 0){
		fprintf(stderr, "Could not connect to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		return -1;
	}
DOT;
	while(1){		/* infinite loop */

		sleep(1);
		cnt = mapi_read_results(fd, fid);
		printf("\nresults: %d\n", *((int*)cnt->res));
		
		//counter,{ res1 },{ res2 },...,{ res_counter }
		tmp = (struct topx_result *)(((int*)cnt->res) + 1);
		
		for(i = 0; i < (*((unsigned int*)cnt->res)); i++){

			printf("\n\tPort: %u ", tmp->value);
			printf("\n\tPackets: %u ", tmp->count);
			printf("\n\tBytes: %llu\n", tmp->bytecount);
			tmp++;
		}
	}

	return 0;
}

void terminate(){

	printf("\nTesting TOP Terminated\n");

	if(mapi_close_flow(fd) < 0){
		fprintf(stderr, "Close flow failed\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		exit(EXIT_FAILURE);
	}

	printf("TOP OK\n");
	exit(EXIT_SUCCESS);
}
