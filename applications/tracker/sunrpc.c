#include "util.h"

void track_sunrpc(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	sunrpc.bytes = 0;
	sunrpc.pkts = 0;
	pthread_mutex_init(&sunrpc.lock, NULL);
	
	if(offline)
	{
		sunrpc.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		sunrpc.fd = mapi_create_flow(DEVICE);
	}

	sunrpc.filter = mapi_apply_function(sunrpc.fd, "BPF_FILTER", "port 111");

	sunrpc.pkt_counter = mapi_apply_function(sunrpc.fd, "PKT_COUNTER");

	sunrpc.byte_counter = mapi_apply_function(sunrpc.fd, "BYTE_COUNTER");

	mapi_connect(sunrpc.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(sunrpc.fd, sunrpc.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(sunrpc.fd, sunrpc.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&sunrpc.lock);
		
		sunrpc.pkts = pkts;
		sunrpc.bytes = bytes;

		pthread_mutex_unlock(&sunrpc.lock);
	}

}
