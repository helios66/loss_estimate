/************************************
 *
 * Testing BPF_FILTER
 *
 ************************************/

#include <stdio.h>
#include <unistd.h>
#include <unistd.h>
#include <mapi.h>
#include "test.h"


int main(int argc, char *argv[])
{
	int fd;
	int fid;
	int fidc, fidf;
	mapi_results_t *cntc, *cntf;
	unsigned long long cntres1, cntres2;
	int err_no;
	char flag=0;
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
	if ((fidc=mapi_apply_function(fd,"PKT_COUNTER")) < 0) {
		fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if ((fid=mapi_apply_function(fd,"BPF_FILTER", "tcp")) < 0) {
		fprintf(stderr, "Could not apply BPF_FILTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if ((fidf=mapi_apply_function(fd,"PKT_COUNTER")) < 0) {
		fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
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

/*
 * sanity check
 */
	usleep(400000);
	cntc = mapi_read_results(fd,fidc);
	cntres1 = *((unsigned long long *)cntc->res);
DOT;
	usleep(400000);
	cntc = mapi_read_results(fd,fidc);
	cntres2 = *((unsigned long long *)cntc->res);
DOT;
	/* the more recent value should be greater or equal to the previous one */
	if (cntres2 < cntres1) {
		fprintf(stderr, "\nWARNING: recent counter (%llu) less than previous (%llu)\n",
			cntres2, cntres1);
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
	fd = fid = fidc = fidf =0;

	if ((fd = mapi_create_flow(argv[1])) < 0) {
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if((fid = mapi_apply_function(fd , "BPF_FILTER" , "RANDOM DATA:1231sad12e1ed2ed:")) == -1) {
		mapi_read_error( &err_no, error);
		printf("Testing error case1. Errorcode: %d  description: %s\n\n" ,err_no, error);
		if(err_no!=1025){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode %d\n" , err_no);
			flag=1;
		}
	}
DOT;
	if((cntc = mapi_read_results(fd,fidc)) == NULL){
		mapi_read_error( &err_no, error);
		printf("Testing error case2. Errrorcode: %d description:%s\n\n" ,err_no, error);
		if(err_no!=6145){
			fprintf(stderr, "\nWARNING: mapi_read_results returned wrong errorcode\n");
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
DOT;

/*
 * Testing offline bpf filter
 *
 */
	fd =0;
	if( (fd=mapi_create_offline_flow("./tracefile", MFF_PCAP)) <0){
		fprintf(stderr,"Could not create offline flow\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if( (fidc=mapi_apply_function(fd,"PKT_COUNTER")) < 0) {
		fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if( (fid=mapi_apply_function(fd,"BPF_FILTER", "tcp")) < 0) {
		fprintf(stderr, "Could not apply BPF_FILTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if( (fidf=mapi_apply_function(fd,"PKT_COUNTER")) < 0) {
		fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
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
	do {
		sleep(1);
		mapi_get_flow_info(fd,&info);
	} while (info.status!=FLOW_FINISHED);
DOT;
	cntc = mapi_read_results(fd,fidc);
DOT;
	cntf = mapi_read_results(fd,fidf);

	/*
	 * Sanity check
	 */
	if( *((int*)cntf->res) == 596 && *((int*)cntc->res) == 893)
		printf("\nOffline BPF_FILTER OK\n");
	else {
		fprintf(stderr, "\nWARNING: offline BPF_FILTER Sanity check failed!!\n\n");
		return -1;
	}
DOT;
	if( (fid = mapi_apply_function(fd , "BPF_FILTER" , "RANDOM DATA:1231sad12e1ed2ed:")) == -1) {
		mapi_read_error( &err_no, error);
		printf("Testing error case2. Errorcode: %d  description: %s\n\n" ,err_no, error);
		if(err_no!=7006){
			fprintf(stderr, "\nWARNING: mapi_apply_function returned wrong errorcode\n");
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
DOT;
	if (!flag) {
		printf("\nBPF_FILTER Error Checking OK\n");
		return 0;
	}
	else{
		fprintf(stderr,"\nBPF_FILTER Error Checking FAILED\n");
		return -1;
	}
}
