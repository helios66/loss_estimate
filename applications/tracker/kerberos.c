#include "util.h"

void track_kerberos(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	kerberos.bytes = 0;
	kerberos.pkts = 0;
	pthread_mutex_init(&kerberos.lock, NULL);
	
	if(offline)
	{
		kerberos.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		kerberos.fd = mapi_create_flow(DEVICE);
	}

	kerberos.filter = mapi_apply_function(kerberos.fd, "BPF_FILTER", "port 88");

	kerberos.pkt_counter = mapi_apply_function(kerberos.fd, "PKT_COUNTER");

	kerberos.byte_counter = mapi_apply_function(kerberos.fd, "BYTE_COUNTER");

	mapi_connect(kerberos.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(kerberos.fd, kerberos.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(kerberos.fd, kerberos.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&kerberos.lock);
		
		kerberos.pkts = pkts;
		kerberos.bytes = bytes;

		pthread_mutex_unlock(&kerberos.lock);
	}

}
