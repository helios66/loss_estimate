#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <mapi.h>
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int fid;
	unsigned long long limit = 50;
	mapi_results_t *run;
	int err_no=0 , flag=0;
	char error[512];
	mapi_flow_info_t info;

	if(argc!=2) // Just for uniformity reasons
	{
		printf("\nWrong Arguments\n");
		return -1;
	}

	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if((fid = mapi_apply_function(fd, "TO_FILE", MFF_PCAP, "/tmp/MAPI_TESTSUITE_DUMMY_TRACE", limit))<0){
		fprintf(stderr, "Could not apply TO_FILE to flow %d\n", fd);
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

	while (12) {
		run = mapi_read_results(fd, fid);

		if(*((int*)run->res)==0) {
			printf("File written.\n");
			break;
		}
		else {
			usleep(10);
		}
	}

	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if (!mapi_is_remote(fd)) {
		printf("WHAT?!?!?!?!?\n");
		if ((fd = mapi_create_offline_flow("/tmp/MAPI_TESTSUITE_DUMMY_TRACE" , MFF_PCAP))<0){
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
		do
		{
		  sleep(1);
		  mapi_get_flow_info(fd,&info);
		} while(info.status!=FLOW_FINISHED);
			run = mapi_read_results(fd, fid);
		if(*((int*)run->res)!=50){
			fprintf(stderr,"\nWARNING: TO_FILE failed to log all the requested pkts\n");
		}
		else
			printf("\nTO_FILE OK!!\n");

		/*
		 * Error checking starts
		 */
DOT;
		if(mapi_close_flow(fd)<0){
			fprintf(stderr,"Close flow failed\n");
			mapi_read_error( &err_no, error);
			fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
			return -1;
		}
DOT;
	}

	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if((fid = mapi_apply_function(fd, "TO_FILE", 13242312, "/tmp/MAPI_TESTSUTE_ERROR_CASES", limit)) < 0){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no!=7006){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode %d\n" , err_no);
			flag=1;
		}

	}
DOT;
	if((fid = mapi_apply_function(fd, "TO_FILE", MFF_PCAP, NULL, limit))< 0){
		mapi_read_error( &err_no, error);
		printf("Testing error case2: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no!=6155){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode %d\n" , err_no);
			flag=1;
		}

	}
DOT;
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
	if (!mapi_is_remote(fd)) {
		system("rm -f /tmp/MAPI_TESTSUITE_DUMMY_TRACE* /tmp/MAPI_TESTSUTE_ERROR_CASES*");
	}
	if (!flag) {
		printf("\nTO_FILE  Error Checking OK\n");
	}
	else{
		fprintf(stderr,"\nTO_FILE Error Checking :FAILED:\n");
		return -1;
	}

	return 0;
}

