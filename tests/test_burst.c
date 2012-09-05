#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <mapi.h>
#include "mapi/burst.h"

#include <string.h>

int main(int argc, char *argv[]) {
	int fd;
	int fid;
	mapi_flow_info_t info;
	mapi_device_info_t dinfo;
	mapi_results_t* res;
	int err_no = 0;
	char error[512];

	void *oldres;
	unsigned int oldres_size;

	unsigned int i;

	unsigned int loop = 0;
	unsigned int loops = 3;
	unsigned int mtime = 3;

	unsigned int min = 0;
	unsigned int max = 10000;
	unsigned int step = 1000;

	unsigned int categories = (max - min) / step + 2;

	unsigned int link_speed;
	unsigned int iftime;
	unsigned int late;
	unsigned int early;

	if (argc == 1) { // no device specified
		fprintf(stderr, "\nWrong arguments\n");
		exit(EXIT_FAILURE);
	}

	// create flow

	if ((fd = mapi_create_flow(argv[1])) < 0) {
		fprintf(stderr, "Could not create flow using '%s'.\n", argv[1]);
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Errorcode: %d description: %s.\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	// get link_speed

	if((mapi_get_flow_info(fd, &info)) < 0){
		fprintf(stderr, "Getting flow info failed on fd:%d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Errorcode: %d description: %s.\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((mapi_get_device_info(info.devid, &dinfo)) < 0){
		fprintf(stderr, "Getting device info failed on fd:%d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Errorcode: %d description: %s.\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if(dinfo.link_speed == 0) {
		fprintf(stderr, "Getting device info failed on fd:%d. Please configure link_speed for device %s in [driver] section of mapi.conf.\n", fd, dinfo.device);
		exit(EXIT_FAILURE);
	}

	link_speed = dinfo.link_speed;

	// calculate iftime

	iftime = (int) 160000 / link_speed; // (12 + 8) * 8

	// set up tolerance

	late = 12304000 / link_speed; // == 1000000000*1538*8/(l_s * 1000000)
	early = 12304000 / link_speed; // == 1000000000*1538*8/(l_s * 1000000)

	// allocate memory to store results in

	if((oldres = malloc(oldres_size = categories * sizeof(burst_category_t))) == NULL) {
		fprintf(stderr, "Could not allocate internal data.\n");
		exit(EXIT_FAILURE);
	}
	memset(oldres, 0, oldres_size);

	// apply function

	if ((fid = mapi_apply_function(fd, "BURST", min, max, step, iftime, late, early, link_speed)) == -1) {
		fprintf(stderr, "Count not apply function BURST to flow %d.\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode: %d description: %s.\n" , err_no, error);
		exit(EXIT_FAILURE);
	}

	//

	if (mapi_connect(fd) < 0) {
		fprintf(stderr, "Could not connect to flow %d.\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode: %d description: %s.\n" , err_no, error);
		exit(EXIT_FAILURE);
	}

	while(loop < loops) {

		printf("Loop: %d / %d (%d seconds per loop)\n", loop, loops, mtime);

		sleep(mtime);

		res = mapi_read_results(fd, fid);
		for(i = 0; i < categories; i++) {
			printf("%d: burst[%d]: %lu bytes, %lu packets, %lu bursts, %lu gap bytes, %lu gaps\n", loop, i,
					((burst_category_t*)res->res)[i].bytes   - ((burst_category_t*)oldres)[i].bytes,
					((burst_category_t*)res->res)[i].packets - ((burst_category_t*)oldres)[i].packets,
					((burst_category_t*)res->res)[i].bursts  - ((burst_category_t*)oldres)[i].bursts,
					((burst_category_t*)res->res)[i].gap_bytes  - ((burst_category_t*)oldres)[i].gap_bytes,
					((burst_category_t*)res->res)[i].gaps  - ((burst_category_t*)oldres)[i].gaps
			);
			((burst_category_t *)oldres)[i] = ((burst_category_t *)res->res)[i];
		}
	
		printf("\n");
		fflush(stdout);
		loop++;

	}

	free(oldres);

	printf("Brust finished.\n");
	return 0;

}
