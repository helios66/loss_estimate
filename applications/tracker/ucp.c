// Universal Computer Protocol 

#include "util.h"

void track_ucp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	ucp.bytes = 0;
	ucp.pkts = 0;
	pthread_mutex_init(&ucp.lock, NULL);
	
	if(offline)
	{
		ucp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		ucp.fd = mapi_create_flow(DEVICE);
	}

	ucp.filter = mapi_apply_function(ucp.fd, "BPF_FILTER", "port 2491");

	ucp.pkt_counter = mapi_apply_function(ucp.fd, "PKT_COUNTER");

	ucp.byte_counter = mapi_apply_function(ucp.fd, "BYTE_COUNTER");

	mapi_connect(ucp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(ucp.fd, ucp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(ucp.fd, ucp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&ucp.lock);
		
		ucp.pkts = pkts;
		ucp.bytes = bytes;

		pthread_mutex_unlock(&ucp.lock);
	}

}
