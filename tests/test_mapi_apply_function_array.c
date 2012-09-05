#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "mapi.h"
#include "test.h"

int main(int argc, char *argv[])
{
	int fd;
	int fid;
	int err_no =0;
	char error[512];
	char* args[3];
	mapi_results_t* res;

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

	args[0]=strdup("contra.gr");
	args[1]=strdup("0");
	args[2]=strdup("0");

	if(mapi_apply_function_array(fd, "STR_SEARCH",&args[0],3)<0){
	  	fprintf(stderr, "Could not apply STR_SEARCH to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	if((fid=mapi_apply_function_array(fd, "PKT_COUNTER", NULL, 0))<0){
	  	fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	if(mapi_connect(fd)<0){
	 	fprintf(stderr, "Connecting to flow failed %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	while (1) {
		res=mapi_read_results(fd,fid);
		printf("contra pkts are %d\n",*((unsigned int*)res->res));
	}

	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	return 0;
}

