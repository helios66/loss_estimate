/*******************************************
 *
 *	Testing PKT_COUNTER
 *
 *******************************************/


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <mapi.h>
#include "../test.h"

int main(int argc, char *argv[])
{
	int fd,fid;
	mapi_results_t *cnt, *cnt2;
	mapi_results_t* res;
	int err_no=0;
	char error[512];


	if(argc!=2){
		  fprintf(stderr, "Wrong Arguments\n");
		  return -1;
	}
		  
	/*while((opt = getopt(argc, argv, "i:r:")) != EOF)
	{
		switch(opt)
		{
			case 'i':
				offline = 0;
				name = (char *)strdup(optarg);
				break;
			case 'r':
				offline = 1;
				name = (char *)strdup(optarg);
				break;
			default:
				break;
		}
	}

	if(offline) {
		fd=mapi_create_offline_flow(name,MFF_PCAP);
		fd2=mapi_create_offline_flow(name,MFF_PCAP);
	}
	else {
		fd=mapi_create_flow(name);
		fd2=mapi_create_flow(name);
	}*/
	
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if((fid=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if(mapi_apply_function(fd,"COOKING",100000,10,0,BOTH_SIDE)<0){
	  	fprintf(stderr, "Could not apply COOKING to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
/*
 * sanity checks
 */	
	usleep(200000); /* 0.2 sec */
DOT;

	res = mapi_read_results(fd, fid);
	printf("\nBytes till now : %llu\n", *((unsigned long long*)res->res));
	/* assuming 40 Gbit/s... :-) */
	if (*((unsigned long long*)res->res) > 1000000000) { /* ~1 GB (40*0.2*10^9/8 bytes) */
		fprintf(stderr, "\nWARNING: suspiciously high byte count (%llu)\n",
			*((unsigned long long *)res->res));
	}

	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;

	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using './tracefile'\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if((fid=mapi_apply_function(fd, "PKT_COUNTER"))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if(mapi_apply_function(fd,"COOKING",100000,10)<0){
	  	fprintf(stderr, "Could not apply COOKING to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

DOT;	
/*
 * sanity checks
 */
	usleep(200000);
	cnt = mapi_read_results(fd,fid);
DOT;	
	cnt2 =mapi_read_results(fd,fid);
DOT;


	if (*((unsigned long long*)cnt->res)!=*((unsigned long long*)cnt2->res) ) { /* ~1 GB (40*0.2*10^9/8 bytes) */
		fprintf(stderr, "\nWARNING: Difference at packet count before and after cooking %llu and %llu respectively\n",
		*((unsigned long long*)cnt->res),
		*((unsigned long long*)cnt2->res));
	}
DOT;
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}


printf("Test of cooking OK\n");
return 0;
}
