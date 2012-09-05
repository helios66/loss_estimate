#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <mapi.h>
#include <mapi/bucket.h>

#define LOOPS 100

int main(int argc, char *argv[])
{
	int fd;
	int fid, fid2;
	mapi_results_t* res;
	int err_no=0;
	char error[512];
	int loop=0;
	struct bucket_data bucket;

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

	if ((fid = mapi_apply_function(fd, "PKT_COUNTER")) == -1) {
		fprintf(stderr, "Count not apply function PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	if ((fid2 = mapi_apply_function(fd, "BUCKET",fd,fid,"1s",1)) == -1) {
		fprintf(stderr, "Count not apply function PKT_COUNTER to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	if (mapi_connect(fd) < 0) {
		fprintf(stderr, "Could not connect to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	while (loop++ <= LOOPS) {
		res = mapi_read_results(fd, fid2);
		bucket = *((struct bucket_data*)res->res);
		printf("\npackets for one second interval: %llu\n", bucket.data);
	}

	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	return 1;
}

