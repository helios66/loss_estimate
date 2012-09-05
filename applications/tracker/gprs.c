#include "util.h"

void track_gprs(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	gprs.bytes = 0;
	gprs.pkts = 0;
	pthread_mutex_init(&gprs.lock, NULL);
	
	if(offline)
	{
		gprs.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		gprs.fd = mapi_create_flow(DEVICE);
	}

	gprs.filter = mapi_apply_function(gprs.fd, "BPF_FILTER", "port 3386");

	gprs.pkt_counter = mapi_apply_function(gprs.fd, "PKT_COUNTER");

	gprs.byte_counter = mapi_apply_function(gprs.fd, "BYTE_COUNTER");

	mapi_connect(gprs.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(gprs.fd, gprs.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(gprs.fd, gprs.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&gprs.lock);
		
		gprs.pkts = pkts;
		gprs.bytes = bytes;

		pthread_mutex_unlock(&gprs.lock);
	}

}
