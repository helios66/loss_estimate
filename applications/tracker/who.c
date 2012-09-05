#include "util.h"

void track_who(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	who.bytes = 0;
	who.pkts = 0;
	pthread_mutex_init(&who.lock, NULL);
	
	
	if(offline)
	{
		who.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		who.fd = mapi_create_flow(DEVICE);
	}

	who.filter = mapi_apply_function(who.fd, "BPF_FILTER", "udp port 513");

	who.pkt_counter = mapi_apply_function(who.fd, "PKT_COUNTER");

	who.byte_counter = mapi_apply_function(who.fd, "BYTE_COUNTER");

	mapi_connect(who.fd);

	
	while(1)
	{
		sleep(2);


		res = mapi_read_results(who.fd, who.pkt_counter);


		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		

		res = mapi_read_results(who.fd, who.byte_counter);


		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&who.lock);
		
		who.pkts = pkts;
		who.bytes = bytes;

		pthread_mutex_unlock(&who.lock);
	}

}
