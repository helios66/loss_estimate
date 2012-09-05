#include "util.h"

void track_ip(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	ip.bytes = 0;
	ip.pkts = 0;
	
	pthread_mutex_init(&ip.lock, NULL);
	
	if(offline)
	{
		ip.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		ip.fd = mapi_create_flow(DEVICE);
	}

	ip.filter = mapi_apply_function(ip.fd, "BPF_FILTER", "ip");

	ip.pkt_counter = mapi_apply_function(ip.fd, "PKT_COUNTER");

	ip.byte_counter = mapi_apply_function(ip.fd, "BYTE_COUNTER");

	mapi_connect(ip.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(ip.fd, ip.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(ip.fd, ip.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&ip.lock);
		
		ip.pkts = pkts;
		ip.bytes = bytes;

		pthread_mutex_unlock(&ip.lock);
	}
}

void track_ip6(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	ip6.bytes = 0;
	ip6.pkts = 0;

	pthread_mutex_init(&ip6.lock, NULL);
	
	if(offline)
	{
		ip6.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		ip6.fd = mapi_create_flow(DEVICE);
	}

	ip6.filter = mapi_apply_function(ip6.fd, "BPF_FILTER", "ip6");

	ip6.pkt_counter = mapi_apply_function(ip6.fd, "PKT_COUNTER");

	ip6.byte_counter = mapi_apply_function(ip6.fd, "BYTE_COUNTER");

	mapi_connect(ip6.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(ip6.fd, ip6.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(ip6.fd, ip6.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&ip6.lock);
		
		ip6.pkts = pkts;
		ip6.bytes = bytes;

		pthread_mutex_unlock(&ip6.lock);
	}
}

void track_arp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	arp.bytes = 0;
	arp.pkts = 0;
	pthread_mutex_init(&arp.lock, NULL);
	
	if(offline)
	{
		arp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		arp.fd = mapi_create_flow(DEVICE);
	}

	arp.filter = mapi_apply_function(arp.fd, "BPF_FILTER", "arp");

	arp.pkt_counter = mapi_apply_function(arp.fd, "PKT_COUNTER");

	arp.byte_counter = mapi_apply_function(arp.fd, "BYTE_COUNTER");

	mapi_connect(arp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(arp.fd, arp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(arp.fd, arp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&arp.lock);
		
		arp.pkts = pkts;
		arp.bytes = bytes;

		pthread_mutex_unlock(&arp.lock);
	}
}

void track_rarp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	rarp.bytes = 0;
	rarp.pkts = 0;
	pthread_mutex_init(&rarp.lock, NULL);
	
	if(offline)
	{
		rarp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		rarp.fd = mapi_create_flow(DEVICE);
	}

	rarp.filter = mapi_apply_function(rarp.fd, "BPF_FILTER", "rarp");

	rarp.pkt_counter = mapi_apply_function(rarp.fd, "PKT_COUNTER");

	rarp.byte_counter = mapi_apply_function(rarp.fd, "BYTE_COUNTER");

	mapi_connect(rarp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(rarp.fd, rarp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(rarp.fd, rarp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&rarp.lock);
		
		rarp.pkts = pkts;
		rarp.bytes = bytes;

		pthread_mutex_unlock(&rarp.lock);
	}
}

void track_atalk(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	atalk.bytes = 0;
	atalk.pkts = 0;
	pthread_mutex_init(&atalk.lock, NULL);
	
	if(offline)
	{
		atalk.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		atalk.fd = mapi_create_flow(DEVICE);
	}

	atalk.filter = mapi_apply_function(atalk.fd, "BPF_FILTER", "atalk");

	atalk.pkt_counter = mapi_apply_function(atalk.fd, "PKT_COUNTER");

	atalk.byte_counter = mapi_apply_function(atalk.fd, "BYTE_COUNTER");

	mapi_connect(atalk.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(atalk.fd, atalk.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(atalk.fd, atalk.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&atalk.lock);
		
		atalk.pkts = pkts;
		atalk.bytes = bytes;

		pthread_mutex_unlock(&atalk.lock);
	}
}

void track_aarp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	aarp.bytes = 0;
	aarp.pkts = 0;
	pthread_mutex_init(&aarp.lock, NULL);
	
	if(offline)
	{
		aarp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		aarp.fd = mapi_create_flow(DEVICE);
	}

	aarp.filter = mapi_apply_function(aarp.fd, "BPF_FILTER", "aarp");

	aarp.pkt_counter = mapi_apply_function(aarp.fd, "PKT_COUNTER");

	aarp.byte_counter = mapi_apply_function(aarp.fd, "BYTE_COUNTER");

	mapi_connect(aarp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(aarp.fd, aarp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(aarp.fd, aarp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&aarp.lock);
		
		aarp.pkts = pkts;
		aarp.bytes = bytes;

		pthread_mutex_unlock(&aarp.lock);
	}
}

void track_decnet(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	decnet.bytes = 0;
	decnet.pkts = 0;
	pthread_mutex_init(&decnet.lock, NULL);
	
	if(offline)
	{
		decnet.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		decnet.fd = mapi_create_flow(DEVICE);
	}

	decnet.filter = mapi_apply_function(decnet.fd, "BPF_FILTER", "decnet");

	decnet.pkt_counter = mapi_apply_function(decnet.fd, "PKT_COUNTER");

	decnet.byte_counter = mapi_apply_function(decnet.fd, "BYTE_COUNTER");

	mapi_connect(decnet.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(decnet.fd, decnet.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(decnet.fd, decnet.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&decnet.lock);
		
		decnet.pkts = pkts;
		decnet.bytes = bytes;

		pthread_mutex_unlock(&decnet.lock);
	}
}

void track_iso(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	iso.bytes = 0;
	iso.pkts = 0;
	pthread_mutex_init(&iso.lock, NULL);
	
	if(offline)
	{
		iso.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		iso.fd = mapi_create_flow(DEVICE);
	}

	iso.filter = mapi_apply_function(iso.fd, "BPF_FILTER", "iso");

	iso.pkt_counter = mapi_apply_function(iso.fd, "PKT_COUNTER");

	iso.byte_counter = mapi_apply_function(iso.fd, "BYTE_COUNTER");

	mapi_connect(iso.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(iso.fd, iso.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(iso.fd, iso.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&iso.lock);
		
		iso.pkts = pkts;
		iso.bytes = bytes;

		pthread_mutex_unlock(&iso.lock);
	}
}

void track_stp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	stp.bytes = 0;
	stp.pkts = 0;
	pthread_mutex_init(&stp.lock, NULL);
	
	if(offline)
	{
		stp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		stp.fd = mapi_create_flow(DEVICE);
	}

	stp.filter = mapi_apply_function(stp.fd, "BPF_FILTER", "stp");

	stp.pkt_counter = mapi_apply_function(stp.fd, "PKT_COUNTER");

	stp.byte_counter = mapi_apply_function(stp.fd, "BYTE_COUNTER");

	mapi_connect(stp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(stp.fd, stp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(stp.fd, stp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&stp.lock);
		
		stp.pkts = pkts;
		stp.bytes = bytes;

		pthread_mutex_unlock(&stp.lock);
	}
}

void track_ipx(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	ipx.bytes = 0;
	ipx.pkts = 0;
	pthread_mutex_init(&ipx.lock, NULL);
	
	if(offline)
	{
		ipx.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		ipx.fd = mapi_create_flow(DEVICE);
	}

	ipx.filter = mapi_apply_function(ipx.fd, "BPF_FILTER", "ipx");

	ipx.pkt_counter = mapi_apply_function(ipx.fd, "PKT_COUNTER");

	ipx.byte_counter = mapi_apply_function(ipx.fd, "BYTE_COUNTER");

	mapi_connect(ipx.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(ipx.fd, ipx.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(ipx.fd, ipx.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&ipx.lock);
		
		ipx.pkts = pkts;
		ipx.bytes = bytes;

		pthread_mutex_unlock(&ipx.lock);
	}
}

void track_sca(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	sca.bytes = 0;
	sca.pkts = 0;
	pthread_mutex_init(&sca.lock, NULL);
	
	if(offline)
	{
		sca.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		sca.fd = mapi_create_flow(DEVICE);
	}

	sca.filter = mapi_apply_function(sca.fd, "BPF_FILTER", "sca");

	sca.pkt_counter = mapi_apply_function(sca.fd, "PKT_COUNTER");

	sca.byte_counter = mapi_apply_function(sca.fd, "BYTE_COUNTER");

	mapi_connect(sca.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(sca.fd, sca.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(sca.fd, sca.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&sca.lock);
		
		sca.pkts = pkts;
		sca.bytes = bytes;

		pthread_mutex_unlock(&sca.lock);
	}
}

void track_lat(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	lat.bytes = 0;
	lat.pkts = 0;
	pthread_mutex_init(&lat.lock, NULL);
	
	if(offline)
	{
		lat.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		lat.fd = mapi_create_flow(DEVICE);
	}

	lat.filter = mapi_apply_function(lat.fd, "BPF_FILTER", "lat");

	lat.pkt_counter = mapi_apply_function(lat.fd, "PKT_COUNTER");

	lat.byte_counter = mapi_apply_function(lat.fd, "BYTE_COUNTER");

	mapi_connect(lat.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(lat.fd, lat.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(lat.fd, lat.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&lat.lock);
		
		lat.pkts = pkts;
		lat.bytes = bytes;

		pthread_mutex_unlock(&lat.lock);
	}
}

void track_mopdl(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	mopdl.bytes = 0;
	mopdl.pkts = 0;
	pthread_mutex_init(&mopdl.lock, NULL);
	
	if(offline)
	{
		mopdl.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		mopdl.fd = mapi_create_flow(DEVICE);
	}

	mopdl.filter = mapi_apply_function(mopdl.fd, "BPF_FILTER", "mopdl");

	mopdl.pkt_counter = mapi_apply_function(mopdl.fd, "PKT_COUNTER");

	mopdl.byte_counter = mapi_apply_function(mopdl.fd, "BYTE_COUNTER");

	mapi_connect(mopdl.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(mopdl.fd, mopdl.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(mopdl.fd, mopdl.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&mopdl.lock);
		
		mopdl.pkts = pkts;
		mopdl.bytes = bytes;

		pthread_mutex_unlock(&mopdl.lock);
	}
}

void track_moprc(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	moprc.bytes = 0;
	moprc.pkts = 0;
	pthread_mutex_init(&moprc.lock, NULL);
	
	if(offline)
	{
		moprc.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		moprc.fd = mapi_create_flow(DEVICE);
	}

	moprc.filter = mapi_apply_function(moprc.fd, "BPF_FILTER", "moprc");

	moprc.pkt_counter = mapi_apply_function(moprc.fd, "PKT_COUNTER");

	moprc.byte_counter = mapi_apply_function(moprc.fd, "BYTE_COUNTER");

	mapi_connect(moprc.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(moprc.fd, moprc.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(moprc.fd, moprc.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&moprc.lock);
		
		moprc.pkts = pkts;
		moprc.bytes = bytes;

		pthread_mutex_unlock(&moprc.lock);
	}
}

void track_netbeui(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	netbeui.bytes = 0;
	netbeui.pkts = 0;
	pthread_mutex_init(&netbeui.lock, NULL);
	
	if(offline)
	{
		netbeui.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		netbeui.fd = mapi_create_flow(DEVICE);
	}

	netbeui.filter = mapi_apply_function(netbeui.fd, "BPF_FILTER", "netbeui");

	netbeui.pkt_counter = mapi_apply_function(netbeui.fd, "PKT_COUNTER");

	netbeui.byte_counter = mapi_apply_function(netbeui.fd, "BYTE_COUNTER");

	mapi_connect(netbeui.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(netbeui.fd, netbeui.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(netbeui.fd, netbeui.byte_counter);

		{
			bytes = *((int*)res->res);;
			res = NULL;
		}
		
		pthread_mutex_lock(&netbeui.lock);
		
		netbeui.pkts = pkts;
		netbeui.bytes = bytes;

		pthread_mutex_unlock(&netbeui.lock);
	}
}
