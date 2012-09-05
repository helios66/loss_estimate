#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ncurses.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netdb.h>
#include <mapi/expiredflowshash.h>
#include <mapi.h>
#include "../test.h"

#define SLEEP 10

#define LOOPS 10

void print_flow(flow_data *data);

int main(int argc, char *argv[]) {

	mapi_results_t *result;
	flow_data *flowdata;
	flows_stat *stats;
	//unsigned int *stats;

	unsigned int i;

	char error[512];
	int  err_no = 0;

	int fd;
	int fid;

	int loops = LOOPS;

	const unsigned int shm_flows = 24900;
	const unsigned int expired_flows_list_size_max = 1249;
	const unsigned int packets_count_min = 2;

	if(argc != 2){
		printf("Usage: %s <interface> \n", argv[0]);
		return -1;
	}
	
	if ((fd = mapi_create_flow(argv[1])) < 0) {
		fprintf(stderr, "Could not create flow using '%s'\n", argv[1]);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode: %d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if ((fid = mapi_apply_function(fd, "EXPIRED_FLOWS", shm_flows, expired_flows_list_size_max, packets_count_min)) < 0) {
		fprintf(stderr, "Count not apply function EXPIRED_FLOWS to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode: %d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	if (mapi_connect(fd) < 0) {
		fprintf(stderr, "Could not connect to flow %d\n", fd);
		mapi_read_error(&err_no, error);
		fprintf(stderr, "Errorcode: %d description: %s\n", err_no, error);
		exit(EXIT_FAILURE);
	}

	// Main loop

	while (loops--) { // Infinite Loop. Forever, report the load and packet loss

		printf("loop %d/%d\n", LOOPS - loops, LOOPS);

		sleep(SLEEP);

		result = (mapi_results_t *) mapi_read_results(fd, fid);
	
		stats = (flows_stat *) result->res;
		flowdata = (struct flow_data *)((char *) result->res + sizeof(flows_stat)); // results/flows array

		for (i = stats->sent; i > 0; i--) {
			print_flow(flowdata);
			flowdata++;
		}
		printf("flows received: %u, expired: %u, sent: %u, ignored: %u, dropped: %u; buffer increase: %d\n", stats->received, stats->expired, stats->sent, stats->ignored, stats->dropped, stats->expired - stats->sent - stats->ignored - stats->dropped);


	}

	if(mapi_close_flow(fd)<0){
		fprintf(stderr,"Close flow failed\n");
		mapi_read_error(&err_no, error);
		fprintf(stderr,"Erorcode :%d description: %s \n" ,err_no, error);
		return -1;
	}

	return 0;
}

void print_flow(flow_data *data) {
	switch (data->ptcl) {
		case IPPROTO_TCP: fprintf(stdout, "TCP "); break;
		case IPPROTO_UDP: fprintf(stdout, "UDP "); break;
		default: fprintf(stdout, "IP "); break;
	}

	fprintf(stdout, "src %d.%d.%d.%d:%d\t", data->saddr.byte1, data->saddr.byte2, data->saddr.byte3, data->saddr.byte4, data->sport);
	fprintf(stdout, "dst %d.%d.%d.%d:%d\t", data->daddr.byte1, data->daddr.byte2, data->daddr.byte3, data->daddr.byte4, data->dport);
	fprintf(stdout, "packets: %lld, bytes: %lld\n", data->packets_count, data->bytes_count);
}

