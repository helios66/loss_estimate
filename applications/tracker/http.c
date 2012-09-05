#include "util.h"

void track_http(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	http.bytes = 0;
	http.pkts = 0;
	pthread_mutex_init(&http.lock, NULL);
	
	if(offline)
	{
		http.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		http.fd = mapi_create_flow(DEVICE);
	}

	http.filter = mapi_apply_function(http.fd, "BPF_FILTER", "port 80");

	http.pkt_counter = mapi_apply_function(http.fd, "PKT_COUNTER");

	http.byte_counter = mapi_apply_function(http.fd, "BYTE_COUNTER");

	mapi_connect(http.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(http.fd, http.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(http.fd, http.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&http.lock);
		
		http.pkts = pkts;
		http.bytes = bytes;

		pthread_mutex_unlock(&http.lock);
	}
}
