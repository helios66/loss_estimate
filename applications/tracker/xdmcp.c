// X-Display Manager Control Protocol

#include "util.h"

void track_xdmcp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	xdmcp.bytes = 0;
	xdmcp.pkts = 0;
	pthread_mutex_init(&xdmcp.lock, NULL);
	
	if(offline)
	{
		xdmcp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		xdmcp.fd = mapi_create_flow(DEVICE);
	}

	xdmcp.filter = mapi_apply_function(xdmcp.fd, "BPF_FILTER", "port 177");

	xdmcp.pkt_counter = mapi_apply_function(xdmcp.fd, "PKT_COUNTER");

	xdmcp.byte_counter = mapi_apply_function(xdmcp.fd, "BYTE_COUNTER");

	mapi_connect(xdmcp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(xdmcp.fd, xdmcp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(xdmcp.fd, xdmcp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&xdmcp.lock);
		
		xdmcp.pkts = pkts;
		xdmcp.bytes = bytes;

		pthread_mutex_unlock(&xdmcp.lock);
	}

}
