#include <stdio.h>
#include <unistd.h>
#include <mapi.h>
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int err_no;
	char flag=0;
	char error[512];
//	struct mapi_stat stats[2];
	struct mapi_stat stats;
	
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
	if(mapi_connect(fd)<0){
	  	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}


	if (mapi_stats(argv[1], &stats)<0) {
		fprintf(stderr, "Error in mapi_stats using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
	
	printf("Results from mapi_stats:\nreceived: %u\ndropped: %u\ndropped by interface: %d\nHostname: %s\nInterface: %s\n",stats.ps_recv,stats.ps_drop,stats.ps_ifdrop,stats.hostname,stats.dev);
//	printf("Results from mapi_stats:\nreceived: %d\ndropped: %d\ndropped by interface: %d\nHostname: %s\nInterface: %s\n",stats[0].ps_recv,stats[0].ps_drop,stats[0].ps_ifdrop,stats[0].hostname,stats[0].dev);
//	printf("Results from mapi_stats:\nreceived: %d\ndropped: %d\ndropped by interface: %d\nHostname: %s\nInterface: %s\n",stats[1].ps_recv,stats[1].ps_drop,stats[1].ps_ifdrop,stats[1].hostname,stats[1].dev);

DOT;	
	if( (fd = mapi_close_flow(fd))<0){
	  	fprintf(stderr, "Mapi Close flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
      }
	
DOT;	
	/*
	 * Error checking 
	 */


	if(!flag)
		printf("\nCreate Flow Error Checking OK\n");
	else {
		fprintf(stderr,"\nCreate Flow Error Checking :FAILED:\n");
		return -1;
	}
	

return 0;
}
