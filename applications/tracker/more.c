#include "util.h"

/*
 * IPP -> Internet Printing Protocol
 */

void track_ipp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	ipp.bytes = 0;
	ipp.pkts = 0;
	pthread_mutex_init(&ipp.lock, NULL);
	
	if(offline)
	{
		ipp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		ipp.fd = mapi_create_flow(DEVICE);
	}

	ipp.filter = mapi_apply_function(ipp.fd, "BPF_FILTER", "port 631");

	ipp.pkt_counter = mapi_apply_function(ipp.fd, "PKT_COUNTER");

	ipp.byte_counter = mapi_apply_function(ipp.fd, "BYTE_COUNTER");

	mapi_connect(ipp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(ipp.fd, ipp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(ipp.fd, ipp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&ipp.lock);
		
		ipp.pkts = pkts;
		ipp.bytes = bytes;

		pthread_mutex_unlock(&ipp.lock);
	}
}

/*
 * HSRP -> Hot Standby Router Protocol
 */

void track_hsrp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	hsrp.bytes = 0;
	hsrp.pkts = 0;
	pthread_mutex_init(&hsrp.lock, NULL);
	
	if(offline)
	{
		hsrp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		hsrp.fd = mapi_create_flow(DEVICE);
	}

	hsrp.filter = mapi_apply_function(hsrp.fd, "BPF_FILTER", "port 1985");

	hsrp.pkt_counter = mapi_apply_function(hsrp.fd, "PKT_COUNTER");

	hsrp.byte_counter = mapi_apply_function(hsrp.fd, "BYTE_COUNTER");

	mapi_connect(hsrp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(hsrp.fd, hsrp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(hsrp.fd, hsrp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&hsrp.lock);
		
		hsrp.pkts = pkts;
		hsrp.bytes = bytes;

		pthread_mutex_unlock(&hsrp.lock);
	}
}

