#include "util.h"

/*
 * this functions traces NETBIOS traffic --> Network Basic Input Output System
 * in 3 ports -> 137, 138, 139
 */
 
void track_netbios(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	netbios.bytes = 0;
	netbios.pkts = 0;
	pthread_mutex_init(&netbios.lock, NULL);
	
	if(offline)
	{
		netbios.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		netbios.fd = mapi_create_flow(DEVICE);
	}

	netbios.filter = mapi_apply_function(netbios.fd, "BPF_FILTER", "port 137 or port 138 or port 139");

	netbios.pkt_counter = mapi_apply_function(netbios.fd, "PKT_COUNTER");

	netbios.byte_counter = mapi_apply_function(netbios.fd, "BYTE_COUNTER");

	mapi_connect(netbios.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(netbios.fd, netbios.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(netbios.fd, netbios.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&netbios.lock);
		
		netbios.pkts = pkts;
		netbios.bytes = bytes;

		pthread_mutex_unlock(&netbios.lock);
	}
}

