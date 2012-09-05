#include "util.h"

void track_torent(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	torent.bytes = 0;
	torent.pkts = 0;
	pthread_mutex_init(&torent.lock, NULL);
	
	if(offline)
	{
		torent.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		torent.fd = mapi_create_flow(DEVICE);
	}

	torent.filter = mapi_apply_function(torent.fd, "BPF_FILTER", "tcp and (port 6881 or port 6882 or port 6883 or port 6884 or port 6885 or port 6886 or port 6887 or port 6888 or port 6889 or port 6890 or port 6891 or port 6892 or port 6893 or port 6894 or port 6895 or port 6896 or port 6897 or port 6898 or port 6899 or port 6969)");

	torent.pkt_counter = mapi_apply_function(torent.fd, "PKT_COUNTER");

	torent.byte_counter = mapi_apply_function(torent.fd, "BYTE_COUNTER");

	mapi_connect(torent.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(torent.fd, torent.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(torent.fd, torent.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&torent.lock);
		
		torent.pkts = pkts;
		torent.bytes = bytes;

		pthread_mutex_unlock(&torent.lock);
	}

}

