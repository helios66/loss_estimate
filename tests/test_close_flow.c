#include <stdio.h>
#include <unistd.h>
#include "mapi.h"
#include "test.h"

int main(MAPI_UNUSED  int argc, char *argv[])
{
	int fd;
	int fid;
	int err_no =0 , flag=0;
	char error[512];
	
	if(!argv[1])
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
	if( (fd = mapi_close_flow(fd))<0){
	  	fprintf(stderr, "Mapi Close flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
      }
	
DOT;	
	printf("\nflow closed succesfully\n");

	/*
	 * Error checking 
	 */

	fd =0;
	
	if( (fd = mapi_close_flow(13244)) == -1){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6145){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;

	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
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
	if( (fd = mapi_close_flow(fd))<0){
	  	fprintf(stderr, "Mapi Close flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
      }
	
DOT;	
	printf("\nflow closed succesfully\n");

	/*
	 * Error checking 
	 */

	fd =0;
	
	if( (fd = mapi_close_flow(13144)) == -1){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6145){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;	
	if(!flag)
		printf("\nClose Flow Error Checking OK\n");
	else 
		printf("\nClose Flow Error Checking :FAILED:\n");

	
	return 0;

}
