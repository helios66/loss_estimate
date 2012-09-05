#include "util.h"

void track_dns(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	dns.bytes = 0;
	dns.pkts = 0;
	pthread_mutex_init(&dns.lock, NULL);
	
	if(offline)
	{
		dns.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		dns.fd = mapi_create_flow(DEVICE);
	}

	dns.filter = mapi_apply_function(dns.fd, "BPF_FILTER", "port 53");

	dns.pkt_counter = mapi_apply_function(dns.fd, "PKT_COUNTER");

	dns.byte_counter = mapi_apply_function(dns.fd, "BYTE_COUNTER");

	mapi_connect(dns.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(dns.fd, dns.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		

		res = mapi_read_results(dns.fd, dns.byte_counter);


		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&dns.lock);
		
		dns.pkts = pkts;
		dns.bytes = bytes;

		pthread_mutex_unlock(&dns.lock);
	}
}

