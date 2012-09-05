#include "util.h"

void track_ssdp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	ssdp.bytes = 0;
	ssdp.pkts = 0;
	pthread_mutex_init(&ssdp.lock, NULL);
	
	if(offline)
	{
		ssdp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		ssdp.fd = mapi_create_flow(DEVICE);
	}

	ssdp.filter = mapi_apply_function(ssdp.fd, "BPF_FILTER", "port 1900");

	ssdp.pkt_counter = mapi_apply_function(ssdp.fd, "PKT_COUNTER");

	ssdp.byte_counter = mapi_apply_function(ssdp.fd, "BYTE_COUNTER");

	mapi_connect(ssdp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(ssdp.fd, ssdp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(ssdp.fd, ssdp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&ssdp.lock);
		
		ssdp.pkts = pkts;
		ssdp.bytes = bytes;

		pthread_mutex_unlock(&ssdp.lock);
	}

}
