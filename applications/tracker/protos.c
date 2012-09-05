#include "util.h"

void track_tcp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	tcp.bytes = 0;
	tcp.pkts = 0;
	pthread_mutex_init(&tcp.lock, NULL);
	
	if(offline)
	{
		tcp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		tcp.fd = mapi_create_flow(DEVICE);
	}

	tcp.filter = mapi_apply_function(tcp.fd, "BPF_FILTER", "tcp");

	tcp.pkt_counter = mapi_apply_function(tcp.fd, "PKT_COUNTER");

	tcp.byte_counter = mapi_apply_function(tcp.fd, "BYTE_COUNTER");

	mapi_connect(tcp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(tcp.fd, tcp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(tcp.fd, tcp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&tcp.lock);
		
		tcp.pkts = pkts;
		tcp.bytes = bytes;

		pthread_mutex_unlock(&tcp.lock);
	}
}

void track_udp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	udp.bytes = 0;
	udp.pkts = 0;
	pthread_mutex_init(&udp.lock, NULL);
	
	if(offline)
	{
		udp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		udp.fd = mapi_create_flow(DEVICE);
	}

	udp.filter = mapi_apply_function(udp.fd, "BPF_FILTER", "udp");

	udp.pkt_counter = mapi_apply_function(udp.fd, "PKT_COUNTER");

	udp.byte_counter = mapi_apply_function(udp.fd, "BYTE_COUNTER");

	mapi_connect(udp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(udp.fd, udp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(udp.fd, udp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&udp.lock);
		
		udp.pkts = pkts;
		udp.bytes = bytes;

		pthread_mutex_unlock(&udp.lock);
	}

}

void track_icmp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	icmp.bytes = 0;
	icmp.pkts = 0;
	pthread_mutex_init(&icmp.lock, NULL);
	
	if(offline)
	{
		icmp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		icmp.fd = mapi_create_flow(DEVICE);
	}

	icmp.filter = mapi_apply_function(icmp.fd, "BPF_FILTER", "icmp");// or icmp6");

	icmp.pkt_counter = mapi_apply_function(icmp.fd, "PKT_COUNTER");

	icmp.byte_counter = mapi_apply_function(icmp.fd, "BYTE_COUNTER");

	mapi_connect(icmp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(icmp.fd, icmp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(icmp.fd, icmp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&icmp.lock);
		
		icmp.pkts = pkts;
		icmp.bytes = bytes;

		pthread_mutex_unlock(&icmp.lock);
	}

}

void track_igmp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	igmp.bytes = 0;
	igmp.pkts = 0;
	pthread_mutex_init(&igmp.lock, NULL);
	
	if(offline)
	{
		igmp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		igmp.fd = mapi_create_flow(DEVICE);
	}

	igmp.filter = mapi_apply_function(igmp.fd, "BPF_FILTER", "igmp");

	igmp.pkt_counter = mapi_apply_function(igmp.fd, "PKT_COUNTER");

	igmp.byte_counter = mapi_apply_function(igmp.fd, "BYTE_COUNTER");

	mapi_connect(igmp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(igmp.fd, igmp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(igmp.fd, igmp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&igmp.lock);
		
		igmp.pkts = pkts;
		igmp.bytes = bytes;

		pthread_mutex_unlock(&igmp.lock);
	}

}

void track_igrp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	igrp.bytes = 0;
	igrp.pkts = 0;
	pthread_mutex_init(&igrp.lock, NULL);
	
	
	if(offline)
	{
		igrp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		igrp.fd = mapi_create_flow(DEVICE);
	}

	igrp.filter = mapi_apply_function(igrp.fd, "BPF_FILTER", "igrp");

	igrp.pkt_counter = mapi_apply_function(igrp.fd, "PKT_COUNTER");

	igrp.byte_counter = mapi_apply_function(igrp.fd, "BYTE_COUNTER");

	mapi_connect(igrp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(igrp.fd, igrp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(igrp.fd, igrp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&igrp.lock);
		
		igrp.pkts = pkts;
		igrp.bytes = bytes;

		pthread_mutex_unlock(&igrp.lock);
	}

}

void track_ah(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	ah.bytes = 0;
	ah.pkts = 0;
	pthread_mutex_init(&ah.lock, NULL);
	
	if(offline)
	{
		ah.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		ah.fd = mapi_create_flow(DEVICE);
	}

	ah.filter = mapi_apply_function(ah.fd, "BPF_FILTER", "ah");

	ah.pkt_counter = mapi_apply_function(ah.fd, "PKT_COUNTER");

	ah.byte_counter = mapi_apply_function(ah.fd, "BYTE_COUNTER");

	mapi_connect(ah.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(ah.fd, ah.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(ah.fd, ah.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&ah.lock);
		
		ah.pkts = pkts;
		ah.bytes = bytes;

		pthread_mutex_unlock(&ah.lock);
	}

}

void track_pim(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	pim.bytes = 0;
	pim.pkts = 0;
	pthread_mutex_init(&pim.lock, NULL);
	
	if(offline)
	{
		pim.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		pim.fd = mapi_create_flow(DEVICE);
	}

	pim.filter = mapi_apply_function(pim.fd, "BPF_FILTER", "pim");

	pim.pkt_counter = mapi_apply_function(pim.fd, "PKT_COUNTER");

	pim.byte_counter = mapi_apply_function(pim.fd, "BYTE_COUNTER");

	mapi_connect(pim.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(pim.fd, pim.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(pim.fd, pim.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&pim.lock);
		
		pim.pkts = pkts;
		pim.bytes = bytes;

		pthread_mutex_unlock(&pim.lock);
	}

}

void track_esp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	esp.bytes = 0;
	esp.pkts = 0;
	pthread_mutex_init(&esp.lock, NULL);
	
	if(offline)
	{
		esp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		esp.fd = mapi_create_flow(DEVICE);
	}

	esp.filter = mapi_apply_function(esp.fd, "BPF_FILTER", "esp");

	esp.pkt_counter = mapi_apply_function(esp.fd, "PKT_COUNTER");

	esp.byte_counter = mapi_apply_function(esp.fd, "BYTE_COUNTER");

	mapi_connect(esp.fd);

	while(1)
	{
		sleep(2);

		res = mapi_read_results(esp.fd, esp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(esp.fd, esp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&esp.lock);
		
		esp.pkts = pkts;
		esp.bytes = bytes;

		pthread_mutex_unlock(&esp.lock);
	}

}

void track_vrrp(void)
{
	int pkts = 0, bytes = 0;
	mapi_results_t *res = NULL;
	vrrp.bytes = 0;
	vrrp.pkts = 0;
	pthread_mutex_init(&vrrp.lock, NULL);
	
	if(offline)
	{
		vrrp.fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		vrrp.fd = mapi_create_flow(DEVICE);
	}

	vrrp.filter = mapi_apply_function(vrrp.fd, "BPF_FILTER", "vrrp");

	vrrp.pkt_counter = mapi_apply_function(vrrp.fd, "PKT_COUNTER");

	vrrp.byte_counter = mapi_apply_function(vrrp.fd, "BYTE_COUNTER");

	mapi_connect(vrrp.fd);

	while(1)
	{
		sleep(2);
		
		res = mapi_read_results(vrrp.fd, vrrp.pkt_counter);

		if(res)
		{
			pkts = *((int*)res->res);
			res = NULL;
		}
		
		res = mapi_read_results(vrrp.fd, vrrp.byte_counter);

		if(res)
		{
			bytes = *((int*)res->res);
			res = NULL;
		}
		
		pthread_mutex_lock(&vrrp.lock);
		
		vrrp.pkts = pkts;
		vrrp.bytes = bytes;

		pthread_mutex_unlock(&vrrp.lock);
	}

}
