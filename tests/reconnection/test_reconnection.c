#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <mapi.h>
#include "mapi/res2file.h"
#include "mapi/pktinfo.h"

int main(int argc, char *argv[]){

	int fd, fd_off, fd_dev, err_no = 0, pkt_size, byte_cnt;
	int pkt_cnt, fid_, fid_1, fid_2, fid_3, fid_4, fid_5, fid_dev;
	char error[512], *devicename, fids[128], types[10], *args[6];
	struct mapipkt *pkt;
	mapi_results_t *res, *res_1, *res_2;
	mapi_flow_info_t info;

	if(argc != 2){
		fprintf(stderr, "\n\tWrong arguments. Usage: %s <iface>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if((fd = mapi_create_flow(argv[1])) < 0){
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((fd_off = mapi_create_offline_flow("../tracefile", MFF_PCAP)) < 0){
		fprintf(stderr, "Could not create offline flow\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((devicename = mapi_create_offline_device("../tracefile", MFF_PCAP)) == NULL){
		fprintf(stderr, "Could not create offline device\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((fd_dev = mapi_create_flow(devicename)) < 0){
		fprintf(stderr, "Could not create flow using '%s'\n", devicename);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((pkt_cnt = mapi_apply_function(fd, "PKT_COUNTER")) == -1){
		fprintf(stderr, "Count not apply function PKT_COUNTER to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((byte_cnt = mapi_apply_function(fd, "BYTE_COUNTER")) == -1){
		fprintf(stderr, "Count not apply function PKT_COUNTER to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((pkt_size = mapi_apply_function(fd, "PKTINFO", PKT_SIZE)) < 0){	// packet size
	  	fprintf(stderr, "Could not apply PKTINFO to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	snprintf(fids, 40, "%d@%d,%d@%d,%d@%d", pkt_cnt, fd, byte_cnt, fd, pkt_size, fd);
	snprintf(types, 10, "%d,%d,%d", R2F_ULLSTR, R2F_ULLSTR, R2F_ULLSTR);

	args[0] = strdup(types);
	args[1] = strdup(fids);
	args[2] = strdup("\t\t\t\t\t*** TEST RECONNECTION ***\n\nPKT_COUNTER | BYTE_COUNTER | PKT_SIZE\n");
	args[3] = strdup("test_reconnection.res");	// created in directory trunk/tests/reconnection/
	args[4] = strdup("3s");				// time interval for writing to file
	args[5] = strdup("0");

	if((mapi_apply_function_array(fd, "RES2FILE", &args[0], 6)) < 0){
	  	fprintf(stderr, "Could not apply RES2FILE to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s \n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((fid_ = mapi_apply_function(fd, "TO_BUFFER", 0)) < 0){
	  	fprintf(stderr, "Could not apply TO_BUFFER to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((fid_1 = mapi_apply_function(fd_off, "PKT_COUNTER")) < 0){
		fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd_off);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((fid_2 = mapi_apply_function(fd_off, "BPF_FILTER", "tcp")) < 0){
		fprintf(stderr, "Could not apply BPF_FILTER to flow %d\n", fd_off);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((fid_3 = mapi_apply_function(fd_off, "PKT_COUNTER")) < 0){
		fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd_off);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((fid_4 = mapi_apply_function(fd_dev, "PKT_COUNTER")) < 0){
		fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd_dev);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((fid_dev = mapi_apply_function(fd_dev, "BPF_FILTER", "udp")) < 0){
		fprintf(stderr, "Could not apply BPF_FILTER to flow %d\n", fd_dev);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((fid_5 = mapi_apply_function(fd_dev, "PKT_COUNTER")) < 0){
		fprintf(stderr, "Could not apply PKT_COUNTER to flow %d\n", fd_dev);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if(mapi_connect(fd_dev) < 0){
		fprintf(stderr, "Could not connect to flow %d\n", fd_dev);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if((mapi_start_offline_device(devicename)) < 0){
		fprintf(stderr, "Could not start device %s\n", devicename);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if(mapi_connect(fd) < 0){
		fprintf(stderr, "Could not connect to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if(mapi_connect(fd_off) < 0){
		fprintf(stderr, "Could not connect to flow %d\n", fd_off);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode :%d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	while(1){

		res = mapi_read_results(fd, pkt_cnt);

		if(res == NULL)	printf("\nMapi read results failed\n");
		else		printf("packets till now : %llu", *((unsigned long long*)res->res));
	
		do{
			mapi_get_flow_info(fd_off, &info);
		}while (info.status != FLOW_FINISHED);

		res_1 = mapi_read_results(fd_off, fid_1);
		res_2 = mapi_read_results(fd_off, fid_3);
		
		if( *((int*)res_2->res) == 596 && *((int*)res_1->res) == 893)
			printf("\t - \tOffline flow BPF_FILTER OK");
		else
			printf("\t - \tWARNING: offline flow BPF_FILTER failed");

		do{
			mapi_get_flow_info(fd_dev, &info);
		}while (info.status != FLOW_FINISHED);

		res_1 = mapi_read_results(fd_dev, fid_4);
		res_2 = mapi_read_results(fd_dev, fid_5);
		
		if( *((int*)res_2->res) == 110 && *((int*)res_1->res) == 893)
			printf("\t - \tOffline device BPF_FILTER OK");
		else
			printf("\t - \tWARNING: offline device BPF_FILTER failed");

		pkt = mapi_get_next_pkt(fd, fid_);
		
		if(pkt == NULL)	printf("\t - \tError in mapi_get_next_packet\n");
		else		printf("\t - \tGot packet\n");

		sleep(1);
	}

	return 0;
}
