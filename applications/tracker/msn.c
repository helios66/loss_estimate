#include "util.h"

void track_msn(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	msn.bytes = 0;
	msn.pkts = 0;
	pthread_mutex_init(&msn.lock, NULL);
	
	if(offline)
	{
		msn.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		msn.fd = mapi_create_flow(DEVICE);
	}

	msn.filter = mapi_apply_function(msn.fd, "BPF_FILTER", "port 1863");

	msn.pkt_counter = mapi_apply_function(msn.fd, "PKT_COUNTER");

	msn.byte_counter = mapi_apply_function(msn.fd, "BYTE_COUNTER");

	mapi_connect(msn.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(msn.fd, msn.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(msn.fd, msn.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&msn.lock);
		
		msn.pkts = pkts;
		msn.bytes = bytes;

		pthread_mutex_unlock(&msn.lock);
	}
}
