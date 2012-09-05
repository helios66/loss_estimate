#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "mapi.h"
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int fid, fid0;
	int level;
	struct mapipkt *pkt;
	mapi_results_t* res = NULL;
	int err_no=0;
	char error[512];
	
	if (argc != 2){
		printf("usage: %s <iface> \n", argv[0]);
		return -1;
	}
	level =1;
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
	if((fid0=mapi_apply_function(fd, "HASH", level))<0){
	  	fprintf(stderr, "Could not apply HASH to flow %d\n", fd);
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
	if((pkt=mapi_get_next_pkt(fd, fid)) != NULL) {
		res=mapi_read_results(fd, fid0);
		printf("hash: %d\n", *(unsigned int*)res->res);
	}
	else {
		fprintf(stderr,"WARNING: Could not get hash from packet\n");
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
	 * Offline testing 
	 */
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if(mapi_apply_function(fd, "BPF_FILTER", "tcp")<0){
	  	fprintf(stderr, "Could not apply BPF_FILTER to flow %d\n", fd);
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
	if((fid0=mapi_apply_function(fd, "HASH", 1))<0){
	  	fprintf(stderr, "Could not apply HASH to flow %d\n", fd);
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
	if((pkt=mapi_get_next_pkt(fd, fid)) != NULL) {
		res=mapi_read_results(fd, fid0);
		printf("hash: %d\n", *(unsigned int*)res->res);
	}
	else {
		fprintf(stderr,"WARNING: Could not get hash from packet\n");
	}
	
	if((*(unsigned int*)res->res)!=2447){
		fprintf(stderr,"WARNING: Sanity check failed results not the expected ones\n");
	}
	
DOT;
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}	
	
return 0;
}

