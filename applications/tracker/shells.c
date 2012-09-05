#include "util.h"

/*
 * This function regognises remote shell connections:
 *
 *	ssh: port 22
 *	telnet: port 23
 *	sshell:	port 614
 *	rtelnet: port 107
 *	telnets: 992	secure telnet
 */

void track_shells(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	shells.bytes = 0;
	shells.pkts = 0;
	pthread_mutex_init(&shells.lock, NULL);
	
	if(offline)
	{
		shells.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		shells.fd = mapi_create_flow(DEVICE);
	}

	shells.filter = mapi_apply_function(shells.fd, "BPF_FILTER", "port 22 or port 23 or port 107 or port 614 or port  992");

	shells.pkt_counter = mapi_apply_function(shells.fd, "PKT_COUNTER");

	shells.byte_counter = mapi_apply_function(shells.fd, "BYTE_COUNTER");

	mapi_connect(shells.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(shells.fd, shells.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(shells.fd, shells.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&shells.lock);
		
		shells.pkts = pkts;
		shells.bytes = bytes;

		pthread_mutex_unlock(&shells.lock);
	}
}

