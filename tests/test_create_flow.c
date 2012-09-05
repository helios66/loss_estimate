#include <stdio.h>
#include <unistd.h>
#include "mapi.h"
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int err_no;
	char flag=0;
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
	/*
	 * Error checking 
	 */
	fd =0;
	
	if( (fd = mapi_create_flow("HOW CARES")) == -1){
		mapi_read_error( &err_no, error);
		printf("Testing error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 3200){
			printf("          Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;

	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using './tracefile'\n");
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

	if(!flag)
		printf("\nCreate Flow Error Checking OK\n");
	else {
		fprintf(stderr,"\nCreate Flow Error Checking :FAILED:\n");
		return -1;
	}
	

return 0;
}
