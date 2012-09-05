#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <mapi.h>
#include "test.h"


int main(int argc, char *argv[])
{
	int fd;
	int fid;
	mapi_results_t* res;
	int err_no=0 , flag=0;
	char error[512];
	mapi_flow_info_t info; 

	if (argc != 2) {
		fprintf(stderr, "\nWrong arguments\n");
		return -1;
	}

	if ((fd = mapi_create_flow(argv[1])) < 0) {
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if ((fid = mapi_apply_function(fd, "PKT_COUNTER")) == -1) {
		fprintf(stderr, "Count not apply function PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if (mapi_connect(fd) < 0) {
		fprintf(stderr, "Could not connect to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	usleep(200000); /* 0.2 sec */
DOT;

	res = mapi_read_results(fd, fid);
	printf("\npackets till now : %llu\n", *((unsigned long long*)res->res));

/*
 * sanity checks
 */
	if (*((unsigned long long*)res->res) > 100000000) {
		fprintf(stderr, "\nWARNING: suspiciously high byte count (%llu)\n",
			*((unsigned long long *)res->res));
	}

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
	if ((fd = mapi_create_flow(argv[1])) < 0) {
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if (mapi_connect(fd) < 0) {
		fprintf(stderr, "Could not connect to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if( ( fid = mapi_apply_function(fd,"PKT_COUNTER", NULL , "ANOTHER1" , 453) ) == -1){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7006){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode\n");
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
	fd =0;
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP)) < 0) {
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if ((fid = mapi_apply_function(fd, "PKT_COUNTER")) == -1) {
		fprintf(stderr, "Count not apply function PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if (mapi_connect(fd) < 0) {
		fprintf(stderr, "Could not connect to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	usleep(200000); /* 0.2 sec */
DOT;

	do
	{
	  sleep(1);
	  mapi_get_flow_info(fd,&info);
	} while(info.status!=FLOW_FINISHED);

	res = mapi_read_results(fd, fid);
	printf("\nPackets till now : %llu\n", *((unsigned long long*)res->res));

/*
 * sanity checks
 */
	if (*((unsigned long long*)res->res)!=893) { 
		fprintf(stderr, "\nWARNING: %llu packtes read instead of 893 \n",
			*((unsigned long long *)res->res));
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
 * Error checking
 */
	if ((fd = mapi_create_offline_flow("./tracefile", MFF_PCAP)) < 0) {
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if (mapi_connect(fd) < 0) {
		fprintf(stderr, "Could not connect to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if( ( fid = mapi_apply_function(fd,"PKT_COUNTER", NULL , "ANOTHER1" , 453) ) == -1){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 7006){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode\n");
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
	if (!flag) {
		printf("\nPacket Counter Error Checking OK\n");
		return 0;
	}
	else{
		fprintf(stderr,"\nPacket Counter Error Checking :FAILED:\n");
		return -1;
	}
}
