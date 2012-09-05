#include "util.h"

void track_eigrp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	eigrp.bytes = 0;
	eigrp.pkts = 0;
	pthread_mutex_init(&eigrp.lock, NULL);
	
	
	if(offline)
	{
		eigrp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		eigrp.fd = mapi_create_flow(DEVICE);
	}

	eigrp.filter = mapi_apply_function(eigrp.fd, "BPF_FILTER", "proto eigrp");//"ip[18] & 88 == 0");

	eigrp.pkt_counter = mapi_apply_function(eigrp.fd, "PKT_COUNTER");

	eigrp.byte_counter = mapi_apply_function(eigrp.fd, "BYTE_COUNTER");

	mapi_connect(eigrp.fd);

	
	while(1)
	{
		sleep(2);


		res = mapi_read_results(eigrp.fd, eigrp.pkt_counter);


		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		

		res = mapi_read_results(eigrp.fd, eigrp.byte_counter);


		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&eigrp.lock);
		
		eigrp.pkts = pkts;
		eigrp.bytes = bytes;

		pthread_mutex_unlock(&eigrp.lock);
	}

}
