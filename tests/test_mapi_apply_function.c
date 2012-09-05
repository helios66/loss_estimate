#include <stdio.h>
#include <unistd.h>
#include "mapi.h"
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int fid;
	int err_no =0 , flag=0;
	char error[512];
	int ok;
	mapi_flow_info_t info;
	
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
	if((ok = mapi_get_flow_info(fd, &info))<0){
	 	fprintf(stderr, "Getting flow info failed on fd:%d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
	/*
	 *Sanity check
	 */
	if(info.num_functions!=1)
		  fprintf(stderr,"WARNING: Apply function sanity check failed\n");
	else 
		  printf("Mapi_apply_function OK\n");
	
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

	fd = fid = 0;
	
	if ((fd = mapi_create_flow(argv[1]))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if( (fid = mapi_apply_function(fd, "IMAGINARY FUNCTION")) == -1){
		mapi_read_error( &err_no, error);
		printf("\nTesting error case1: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6144){
			fprintf(stderr,"WARNING:Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;	
	if( (fid = mapi_apply_function(-12314, "TO_BUFFER")) == -1){
		mapi_read_error( &err_no, error);
		printf("\nTesting error case2: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6147){
			fprintf(stderr,"WARNING:Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;	
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
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
	 *Offline checking
	 */
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
	if((ok = mapi_get_flow_info(fd, &info))<0){
	 	fprintf(stderr, "Getting flow info failed on fd:%d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
	/*
	 *Sanity check
	 */
	if(info.num_functions!=1)
		  fprintf(stderr,"WARNING: Apply function sanity check failed\n");
	else 
		  printf("Mapi_apply_function OK\n");
	
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

	fd = fid = 0;
	
	if ((fd = mapi_create_offline_flow("./tracefile" , MFF_PCAP))<0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;

	if( (fid = mapi_apply_function(fd, "IMAGINARY FUNCTION")) == -1){
		mapi_read_error( &err_no, error);
		printf("\nTesting error case3: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6144){
			fprintf(stderr,"WARNING:Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;	
	if( (fid = mapi_apply_function(-12314, "TO_BUFFER")) == -1){
		mapi_read_error( &err_no, error);
		printf("\nTesting error case4: Errorcode :%d description: %s \n" ,err_no, error);
		if(err_no != 6147){
			fprintf(stderr,"WARNING:Wrong ERRORCODE returned\n");
			flag = 1;	
		}
	}
DOT;	
	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;
	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
DOT;


	if(!flag)
		printf("\nMAPI apply function Error Checking OK\n");
	else 
		printf("\nMAPI apply function Error Checking :FAILED:\n");


	return 0;
}

