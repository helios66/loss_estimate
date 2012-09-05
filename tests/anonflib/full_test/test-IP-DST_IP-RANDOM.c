#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <mapi.h>
#include <mapi/pktinfo.h>
#include "../../test.h"

int main(MAPI_UNUSED int argc, char *argv[])
{
	int fd;
	mapi_flow_info_t info;
	int err_no;
	char error[512];

	if((fd = mapi_create_offline_flow(argv[1], MFF_PCAP)) < 0) {
		fprintf(stderr,"Could not create offline flow\n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
	DOT;
	if(mapi_apply_function(fd, "ANONYMIZE", "IP,DST_IP,RANDOM") < 0) {
		printf("Could not apply ANONYMIZE IP,DST_IP,RANDOM \n");
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
	DOT;
	if(mapi_apply_function(fd, "TO_FILE", MFF_PCAP, argv[2], 0) < 0) {
		fprintf(stderr, "Could not apply TO_FILE to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
	DOT;
	if (mapi_connect(fd) < 0) {
		fprintf(stderr,"Could not connect to flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
	DOT;

	do {
		if(mapi_get_flow_info(fd, &info) < 0) {
			fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd);
			mapi_read_error( &err_no, error);
			fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
			return -1;
		}
		DOT;
	}while(info.status != FLOW_FINISHED);

	if (mapi_close_flow(fd) < 0) {
		fprintf(stderr, "Could not close flow %d\n", fd);
		mapi_read_error( &err_no, error);
		fprintf(stderr,"Errorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}
	DOT;

	return 0;
}
						
