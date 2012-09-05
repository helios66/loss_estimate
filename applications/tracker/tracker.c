#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include "util.h"

//char*  DEVICE="eth0";

void usage(void);
void panic(char *fmt, ...);

static char *progname;

int main(int argc, char **argv)
{

	int opt;
	int fd = 0;
	int fpktc = 0, fbytec = 0;
	int pktc = 0, bytec = 0;
	int allpkts = 0, allbytes = 0;
	int ippkts = 0, ipbytes = 0;

	pid_t pid;
	pthread_t thread_id;
	mapi_results_t *res = NULL;
	offline = 0;

	int flag;
	int fileftp, filekaz;
	int ftp_pipefd[2];
	int kaz_pipefd[2];
	char pipebuf[20];

	DEVICE=strdup("eth0");

	kazaa.pkts = 0;
	kazaa.bytes = 0;
	ftp.pkts = 0;
	ftp.bytes = 0;
	nap.pkts = 0;
	nap.bytes = 0;
	mail.pkts = 0;
	mail.bytes = 0;
	dns.pkts = 0;
	dns.bytes = 0;
	realaudio.pkts = 0;
	realaudio.bytes = 0;
	
	progname = strdup(argv[0]);

	while((opt = getopt(argc, argv, "hv:r:w:d:")) != EOF)
	{
		switch(opt)
		{
			case 'h':
				usage();
				break;
			case 'r':
				offline = 1;
				readfile = (char *)strdup(optarg);
				break;
			case 'w':
				tofile = 1;
				writefile = (char *)strdup(optarg);
				break;
			case 'd':
				DEVICE=strdup(optarg);
				break;
			default:
				panic("missing argument to -%c\n", optopt);
		}
	}
	
	fileftp = open("shareftp.bin", O_RDWR | O_CREAT);
	write(fileftp, &pktc, (sizeof(int) + sizeof(pthread_mutex_t)) + 2 * sizeof(int));

	ftp_flag = (int *)mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED, fileftp, 0);
	ftp_mutex = (pthread_mutex_t *)mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, fileftp, 0);

	filekaz = open("sharekaz.bin", O_RDWR | O_CREAT);
	write(filekaz, &pktc, (sizeof(int) + sizeof(pthread_mutex_t)) + 2 * sizeof(int));

	kaz_flag = (int *)mmap(NULL, sizeof(int), PROT_READ|PROT_WRITE, MAP_SHARED, filekaz, 0);
	kaz_mutex = (pthread_mutex_t *)mmap(NULL, sizeof(pthread_mutex_t), PROT_READ|PROT_WRITE, MAP_SHARED, filekaz, 0);
	*ftp_flag = 0;
	*kaz_flag = 0;
	
	pthread_mutex_init(ftp_mutex, NULL); 
	pthread_mutex_init(kaz_mutex, NULL);

	if(pipe(ftp_pipefd) == -1)
	{
		perror("pipe");
        ////exit(1);
	}

	// fork for track_ftp
	
	if((pid = fork()) == -1)
	{
		perror("error::fork::process not created\n");
	}
	else if(pid == 0)
	{
		track_ftp(ftp_pipefd);
	}

	if(pipe(kaz_pipefd) == -1)
	{
		perror("pipe");
        exit(1);
	}


	// fork for track_kazza

	if((pid = fork()) == -1)
	{
		perror("error::fork::process not created\n");
	}
	else if(pid == 0)
	{
		track_kazza(kaz_pipefd);
	}
	
	close(ftp_pipefd[1]);
	close(kaz_pipefd[1]);
	
	if(offline)
	{
		fd = mapi_create_offline_flow(readfile, MFF_PCAP);
	}
	else
	{
		fd = mapi_create_flow(DEVICE);
	}

	if(fd < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("main:Error: %d - %s\n", err_no, err_buffer);
	}	

	fpktc = mapi_apply_function(fd, "PKT_COUNTER");

	if(fpktc < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("main:Error: %d - %s\n", err_no, err_buffer);
	}	

	fbytec = mapi_apply_function(fd, "BYTE_COUNTER");
	
	if(fbytec < 0)
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("main:Error: %d - %s\n", err_no, err_buffer);
	}

	if(tofile)
	{
		mapi_apply_function(fd, "TO_FILE", MFF_PCAP, writefile, 0);
	}

	if(mapi_connect(fd) < 0)	
	{
		char err_buffer[1024];
		int err_no;
		mapi_read_error(&err_no,err_buffer);
		printf("main:Error: %d - %s\n", err_no, err_buffer);
	}

	/*
	 * Ethernet Protocols Tracking threads
	 */
	 
	if(pthread_create(&thread_id, NULL, (void *)track_ip, NULL) != 0)
	{
		perror("error::pthread_create::track_arp");
	}
	
/*	if(pthread_create(&thread_id, NULL, (void *)track_ip6, NULL) != 0)
	{
		perror("error::pthread_create::track_arp");
	}
*/	
	if(pthread_create(&thread_id, NULL, (void *)track_arp, NULL) != 0)
	{
		perror("error::pthread_create::track_arp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_rarp, NULL) != 0)
	{
		perror("error::pthread_create::track_arp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_atalk, NULL) != 0)
	{
		perror("error::pthread_create::track_arp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_aarp, NULL) != 0)
	{
		perror("error::pthread_create::track_arp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_decnet, NULL) != 0)
	{
		perror("error::pthread_create::track_arp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_iso, NULL) != 0)
	{
		perror("error::pthread_create::track_arp");
	}
	if(pthread_create(&thread_id, NULL, (void *)track_stp, NULL) != 0)
	{
		perror("error::pthread_create::track_stp");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_ipx, NULL) != 0)
	{
		perror("error::pthread_create::track_ipx");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_sca, NULL) != 0)
	{
		perror("error::pthread_create::track_sca");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_lat, NULL) != 0)
	{
		perror("error::pthread_create::track_lat");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_mopdl, NULL) != 0)
	{
		perror("error::pthread_create::track_mopdl");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_moprc, NULL) != 0)
	{
		perror("error::pthread_create::track_moprc");
		
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_netbeui, NULL) != 0)
	{
		perror("error::pthread_create::track_netbeui");
	}

	/*
	 * Internet Protocols Tracking threads
	 */
	 
	if(pthread_create(&thread_id, NULL, (void *)track_tcp, NULL) != 0)
	{
		perror("error::pthread_create::track_tcp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_udp, NULL) != 0)
	{
		perror("error::pthread_create::track_udp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_icmp, NULL) != 0)
	{
		perror("error::pthread_create::track_icmp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_igmp, NULL) != 0)
	{
		perror("error::pthread_create::track_igmp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_igrp, NULL) != 0)
	{
		perror("error::pthread_create::track_igrp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_pim, NULL) != 0)
	{
		perror("error::pthread_create::track_pim");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_ah, NULL) != 0)
	{
		perror("error::pthread_create::track_ah");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_esp, NULL) != 0)
	{
		perror("error::pthread_create::track_esp");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_vrrp, NULL) != 0)
	{
		perror("error::pthread_create::track_vrrp");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_eigrp, NULL) != 0)
	{
		perror("error::pthread_create::track_eigrp");
	}

	/*
	 *	Internet Application Tracking threads
	 */
	 
	if(pthread_create(&thread_id, NULL, (void *)track_torent, NULL) != 0)
	{
		perror("error::pthread_create::track_torent");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_nap, NULL) != 0)
	{
		perror("error::pthread_create::track_nap");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_mail, NULL) != 0)
	{
		perror("error::pthread_create::track_mail");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_http, NULL) != 0)
	{
		perror("error::pthread_create::track_http");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_dns, NULL) != 0)
	{
		perror("error::pthread_create::track_dns");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_msn, NULL) != 0)
	{
		perror("error::pthread_create::track_msn");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_netbios, NULL) != 0)
	{
		perror("error::pthread_create::track_netbios");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_shells, NULL) != 0)
	{
		perror("error::pthread_create::track_shells");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_ipp, NULL) != 0)
	{
		perror("error::pthread_create::track_ipp");
	}
	
	if(pthread_create(&thread_id, NULL, (void *)track_hsrp, NULL) != 0)
	{
		perror("error::pthread_create::track_hsrp");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_gprs, NULL) != 0)
	{
		perror("error::pthread_create::track_gprs");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_kerberos, NULL) != 0)
	{
		perror("error::pthread_create::track_kerberos");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_sunrpc, NULL) != 0)
	{
		perror("error::pthread_create::track_sunrpc");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_ssdp, NULL) != 0)
	{
		perror("error::pthread_create::track_ssdp");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_ucp, NULL) != 0)
	{
		perror("error::pthread_create::track_ucp");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_who, NULL) != 0)
	{
		perror("error::pthread_create::track_who");
	}

	if(pthread_create(&thread_id, NULL, (void *)track_xdmcp, NULL) != 0)
	{
		perror("error::pthread_create::track_xdmcp");
	}

	while(1)
	{
		sleep(1);

		res = mapi_read_results(fd, fpktc);
	
		if(res)
		{
			pktc = *((int*)res->res);

			res = NULL;
		}

		res = mapi_read_results(fd, fbytec);
	
		if(res)
		{
			bytec = *((int*)res->res);

			res = NULL;
		}

		system("clear");

		printf("================================================================================\n");
		printf("=\t\tETHERNET PROTOCOL IDENTIFICATION\n");
		printf("================================================================================\n");

		printf("=\tALL TRAFFIC\t:\t%d pkts %d bytes\n", pktc, bytec);

		allpkts = allbytes = 0;
	
		// locking the mutex
		pthread_mutex_lock(&ip.lock);

		allpkts += ip.pkts;
		allbytes += ip.bytes;
	
		printf("=\tIP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", ip.pkts, (double)((ip.pkts*100.0)/pktc), ip.bytes ,(double)((ip.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&ip.lock);

		// locking the mutex
		pthread_mutex_lock(&ip6.lock);

		allpkts += ip6.pkts;
		allbytes += ip6.bytes;
	
		printf("=\tIPv6 TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", ip6.pkts, (double)((ip6.pkts*100.0)/pktc), ip6.bytes ,(double)((ip6.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&ip6.lock);

		ippkts = allpkts;
		ipbytes = allbytes;

		// locking the mutex
		pthread_mutex_lock(&arp.lock);
		
		allpkts += arp.pkts;
		allbytes += arp.bytes;

		printf("=\tARP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", arp.pkts, (double)((arp.pkts*100.0)/pktc), arp.bytes ,(double)((arp.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&arp.lock);

		// locking the mutex
		pthread_mutex_lock(&rarp.lock);
		
		allpkts += rarp.pkts;
		allbytes += rarp.bytes;

		printf("=\tRARP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", rarp.pkts, (double)((rarp.pkts*100.0)/pktc), rarp.bytes ,(double)((rarp.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&rarp.lock);

		// locking the mutex
		pthread_mutex_lock(&atalk.lock);
		
		allpkts += atalk.pkts;
		allbytes += atalk.bytes;

		printf("=\tATALK TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", atalk.pkts, (double)((atalk.pkts*100.0)/pktc), atalk.bytes ,(double)((atalk.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&atalk.lock);

		// locking the mutex
		pthread_mutex_lock(&aarp.lock);
		
		allpkts += aarp.pkts;
		allbytes += aarp.bytes;

		printf("=\tAARP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", aarp.pkts, (double)((aarp.pkts*100.0)/pktc), aarp.bytes ,(double)((aarp.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&aarp.lock);

		// locking the mutex
		pthread_mutex_lock(&decnet.lock);
		
		allpkts += decnet.pkts;
		allbytes += decnet.bytes;

		printf("=\tDECNET TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", decnet.pkts, (double)((decnet.pkts*100.0)/pktc), decnet.bytes ,(double)((decnet.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&decnet.lock);

		// locking the mutex
		pthread_mutex_lock(&iso.lock);
		
		allpkts += iso.pkts;
		allbytes += iso.bytes;

		printf("=\tISO TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", iso.pkts, (double)((iso.pkts*100.0)/pktc), iso.bytes ,(double)((iso.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&iso.lock);
	
		// locking the mutex
		pthread_mutex_lock(&stp.lock);
		
		allpkts += stp.pkts;
		allbytes += stp.bytes;

		printf("=\tSTP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", stp.pkts, (double)((stp.pkts*100.0)/pktc), stp.bytes ,(double)((stp.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&stp.lock);

		// locking the mutex
		pthread_mutex_lock(&ipx.lock);
		
		allpkts += ipx.pkts;
		allbytes += ipx.bytes;

		printf("=\tIPX TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", ipx.pkts, (double)((ipx.pkts*100.0)/pktc), ipx.bytes ,(double)((ipx.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&ipx.lock);
	
		// locking the mutex
		pthread_mutex_lock(&sca.lock);
		
		allpkts += sca.pkts;
		allbytes += sca.bytes;

		printf("=\tSCA TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", sca.pkts, (double)((sca.pkts*100.0)/pktc), sca.bytes ,(double)((sca.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&sca.lock);
	
		// locking the mutex
		pthread_mutex_lock(&lat.lock);
		
		allpkts += lat.pkts;
		allbytes += lat.bytes;

		printf("=\tLAT TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", lat.pkts, (double)((lat.pkts*100.0)/pktc), lat.bytes ,(double)((lat.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&lat.lock);
			
		// locking the mutex
		pthread_mutex_lock(&mopdl.lock);
		
		allpkts += mopdl.pkts;
		allbytes += mopdl.bytes;

		printf("=\tMOPDL TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", mopdl.pkts, (double)((mopdl.pkts*100.0)/pktc), mopdl.bytes ,(double)((mopdl.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&mopdl.lock);

		// locking the mutex
		pthread_mutex_lock(&moprc.lock);
		
		allpkts += moprc.pkts;
		allbytes += moprc.bytes;

		printf("=\tMOPRC TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", moprc.pkts, (double)((moprc.pkts*100.0)/pktc), moprc.bytes ,(double)((moprc.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&moprc.lock);

		// locking the mutex
		pthread_mutex_lock(&netbeui.lock);
		
		allpkts += netbeui.pkts;
		allbytes += netbeui.bytes;

		printf("=\tNETBEUI TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", netbeui.pkts, (double)((netbeui.pkts*100.0)/pktc), netbeui.bytes ,(double)((netbeui.bytes*100.0)/bytec));
		
		// unlocking the mutex
		pthread_mutex_unlock(&netbeui.lock);

		printf("=\n=\tOTHER TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", pktc - allpkts, (double)(((pktc - allpkts)*100.0)/pktc), bytec - allbytes ,(double)(((bytec - allbytes)*100.0)/bytec));

		printf("================================================================================\n");
		printf("=\t\tINTERNET PROTOCOL IDENTIFICATION\n");
		printf("================================================================================\n");

		printf("=\tALL IP TRAFFIC\t:\t%d pkts %d bytes\n", ippkts, ipbytes);

		allpkts = allbytes = 0;
	
		// locking the mutex
		pthread_mutex_lock(&tcp.lock);

		allpkts += tcp.pkts;
		allbytes += tcp.bytes;
	
		printf("=\tTCP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", tcp.pkts, (double)((tcp.pkts*100.0)/ippkts), tcp.bytes ,(double)((tcp.bytes*100.0)/ipbytes));
		
		// unlocking the mutex
		pthread_mutex_unlock(&tcp.lock);

		// locking the mutex
		pthread_mutex_lock(&udp.lock);
		
		allpkts += udp.pkts;
		allbytes += udp.bytes;

		printf("=\tUDP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", udp.pkts, (double)((udp.pkts*100.0)/ippkts), udp.bytes ,(double)((udp.bytes*100.0)/ipbytes));
		
		// unlocking the mutex
		pthread_mutex_unlock(&udp.lock);

		// locking the mutex
		pthread_mutex_lock(&icmp.lock);
		
		allpkts += icmp.pkts;
		allbytes += icmp.bytes;

		printf("=\tICMP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", icmp.pkts, (double)((icmp.pkts*100.0)/ippkts), icmp.bytes ,(double)((icmp.bytes*100.0)/ipbytes));
		
		// unlocking the mutex
		pthread_mutex_unlock(&icmp.lock);

		// locking the mutex
		pthread_mutex_lock(&igmp.lock);
		
		allpkts += igmp.pkts;
		allbytes += igmp.bytes;

		printf("=\tIGMP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", igmp.pkts, (double)((igmp.pkts*100.0)/ippkts), igmp.bytes ,(double)((igmp.bytes*100.0)/ipbytes));
		
		// unlocking the mutex
		pthread_mutex_unlock(&igmp.lock);

		// locking the mutex
		pthread_mutex_lock(&igrp.lock);
		
		allpkts += igrp.pkts;
		allbytes += igrp.bytes;

		printf("=\tIGRP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", igrp.pkts, (double)((igrp.pkts*100.0)/ippkts), igrp.bytes ,(double)((igrp.bytes*100.0)/ipbytes));
		
		// unlocking the mutex
		pthread_mutex_unlock(&igrp.lock);

		// locking the mutex
		pthread_mutex_lock(&pim.lock);
		
		allpkts += pim.pkts;
		allbytes += pim.bytes;

		printf("=\tPIM TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", pim.pkts, (double)((pim.pkts*100.0)/ippkts), pim.bytes ,(double)((pim.bytes*100.0)/ipbytes));
		
		// unlocking the mutex
		pthread_mutex_unlock(&pim.lock);

		// locking the mutex
		pthread_mutex_lock(&ah.lock);
		
		allpkts += ah.pkts;
		allbytes += ah.bytes;

		printf("=\tAH TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", ah.pkts, (double)((ah.pkts*100.0)/ippkts), ah.bytes ,(double)((ah.bytes*100.0)/ipbytes));
		
		// unlocking the mutex
		pthread_mutex_unlock(&ah.lock);

		// locking the mutex
		pthread_mutex_lock(&esp.lock);
		
		allpkts += esp.pkts;
		allbytes += esp.bytes;

		printf("=\tESP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", esp.pkts, (double)((esp.pkts*100.0)/ippkts), esp.bytes ,(double)((esp.bytes*100.0)/ipbytes));
		
		// unlocking the mutex
		pthread_mutex_unlock(&esp.lock);

		// locking the mutex
		pthread_mutex_lock(&vrrp.lock);
		
		allpkts += vrrp.pkts;
		allbytes += vrrp.bytes;

		printf("=\tVRRP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", vrrp.pkts, (double)((vrrp.pkts*100.0)/ippkts), vrrp.bytes ,(double)((vrrp.bytes*100.0)/ipbytes));
		
		// unlocking the mutex
		pthread_mutex_unlock(&vrrp.lock);

		pthread_mutex_lock(&eigrp.lock);
		
		allpkts += eigrp.pkts;
		allbytes += eigrp.bytes;

		printf("=\tEIGRP TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", eigrp.pkts, (double)((eigrp.pkts*100.0)/ippkts), eigrp.bytes ,(double)((eigrp.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&eigrp.lock);



		printf("=\n=\tOTHER TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", ippkts - allpkts, (double)(((ippkts - allpkts)*100.0)/ippkts), ipbytes - allbytes ,(double)(((ipbytes - allbytes)*100.0)/ipbytes));

		allpkts = allbytes = 0;
		
	printf("================================================================================\n");
	printf("=\t\tINTERNET APPLICATION IDENTIFICATION\n");
	printf("================================================================================\n");

		printf("=\tALL TCP/UDP TRAFFIC\t\t:\t%d pkts %d bytes\n", ippkts, ipbytes);
		
		flag = 0;

		pthread_mutex_lock(kaz_mutex);

		flag = *kaz_flag;

		if(flag)
			*kaz_flag -= 1;

		pthread_mutex_unlock(kaz_mutex);

		msync(&filekaz, (sizeof(int) + sizeof(pthread_mutex_t)), MS_SYNC|MS_INVALIDATE);

		if(flag >= 1)
		{
			if(read(kaz_pipefd[0], (void *)pipebuf, 200) == -1)
			{
				printf("error\n");
			}
			else
			{
				sscanf(pipebuf, "%d %d", &kazaa.pkts, &kazaa.bytes);
			}
			
			flag = 0;
		}

		allpkts += kazaa.pkts;
		allbytes += kazaa.bytes;

		
		printf("=\tKAZAA TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", kazaa.pkts, (double)((kazaa.pkts*100.0)/ippkts), kazaa.bytes ,(double)((kazaa.bytes*100.0)/ipbytes));	

		flag = 0;

		pthread_mutex_lock(ftp_mutex);

		flag = *ftp_flag;

		if(flag)
		*ftp_flag -= 1;

		pthread_mutex_unlock(ftp_mutex);

		if(flag >= 1)
		{
			if(read(ftp_pipefd[0], (void *)pipebuf, 100) == -1)
			{
				printf("error\n");
			}
			else
			{
				sscanf(pipebuf, "%d %d", &ftp.pkts, &ftp.bytes);
			}
			
			flag = 0;
		}

		allpkts += ftp.pkts;
		allbytes += ftp.bytes;

		printf("=\tFTP TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", ftp.pkts, (double)((ftp.pkts*100.0)/ippkts), ftp.bytes ,(double)((ftp.bytes*100.0)/ipbytes));

		pthread_mutex_lock(&torent.lock);
		
		allpkts += torent.pkts;
		allbytes += torent.bytes;

		printf("=\tBITTORENT TRAFFIC\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", torent.pkts, (double)((torent.pkts*100.0)/ippkts), torent.bytes ,(double)((torent.bytes*100.0)/ipbytes));
	
		pthread_mutex_unlock(&torent.lock);

		pthread_mutex_lock(&nap.lock);
		
		allpkts += nap.pkts;
		allbytes += nap.bytes;

		printf("=\tNAPSTER TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", nap.pkts, (double)((nap.pkts*100.0)/ippkts), nap.bytes ,(double)((nap.bytes*100.0)/ipbytes));
	
		pthread_mutex_unlock(&nap.lock);

		pthread_mutex_lock(&mail.lock);
		
		allpkts += mail.pkts;
		allbytes += mail.bytes;

		printf("=\tMAIL TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", mail.pkts, (double)((mail.pkts*100.0)/ippkts), mail.bytes ,(double)((mail.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&mail.lock);
	
		pthread_mutex_lock(&http.lock);
		
		allpkts += http.pkts;
		allbytes += http.bytes;

		printf("=\tHTTP TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", http.pkts, (double)((http.pkts*100.0)/ippkts), http.bytes ,(double)((http.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&http.lock);
	
		pthread_mutex_lock(&dns.lock);
		
		allpkts += dns.pkts;
		allbytes += dns.bytes;

		printf("=\tDNS TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", dns.pkts, (double)((dns.pkts*100.0)/ippkts), dns.bytes ,(double)((dns.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&dns.lock);
	
		pthread_mutex_lock(&msn.lock);
		
		allpkts += msn.pkts;
		allbytes += msn.bytes;

		printf("=\tMSN TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", msn.pkts, (double)((msn.pkts*100.0)/ippkts), msn.bytes ,(double)((msn.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&msn.lock);
	
		pthread_mutex_lock(&netbios.lock);
		
		allpkts += netbios.pkts;
		allbytes += netbios.bytes;

		printf("=\tNETBIOS TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", netbios.pkts, (double)((netbios.pkts*100.0)/ippkts), netbios.bytes ,(double)((netbios.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&netbios.lock);

		pthread_mutex_lock(&shells.lock);
		
		allpkts += shells.pkts;
		allbytes += shells.bytes;

		printf("=\tREMOTE SHELL TRAFFIC\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", shells.pkts, (double)((shells.pkts*100.0)/ippkts), shells.bytes ,(double)((shells.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&shells.lock);

		pthread_mutex_lock(&ipp.lock);
		
		allpkts += ipp.pkts;
		allbytes += ipp.bytes;

		printf("=\tPRINTING(IPP) TRAFFIC\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", ipp.pkts, (double)((ipp.pkts*100.0)/ippkts), ipp.bytes ,(double)((ipp.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&ipp.lock);

		pthread_mutex_lock(&hsrp.lock);
		
		allpkts += hsrp.pkts;
		allbytes += hsrp.bytes;

		printf("=\tROUTER PROTOCOL(HSRP) TRAFFIC\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", hsrp.pkts, (double)((hsrp.pkts*100.0)/ippkts), hsrp.bytes ,(double)((hsrp.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&hsrp.lock);

		pthread_mutex_lock(&gprs.lock);
		
		allpkts += gprs.pkts;
		allbytes += gprs.bytes;

		printf("=\tGPRS TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", gprs.pkts, (double)((gprs.pkts*100.0)/ippkts), gprs.bytes ,(double)((gprs.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&gprs.lock);

		pthread_mutex_lock(&kerberos.lock);
		
		allpkts += kerberos.pkts;
		allbytes += kerberos.bytes;

		printf("=\tKERBEROS TRAFFIC\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", kerberos.pkts, (double)((kerberos.pkts*100.0)/ippkts), kerberos.bytes ,(double)((kerberos.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&kerberos.lock);

		pthread_mutex_lock(&sunrpc.lock);
		
		allpkts += sunrpc.pkts;
		allbytes += sunrpc.bytes;
		
		printf("=\tSUNRPC TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", sunrpc.pkts, (double)((sunrpc.pkts*100.0)/ippkts), sunrpc.bytes ,(double)((sunrpc.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&sunrpc.lock);

		pthread_mutex_lock(&ssdp.lock);
		
		allpkts += ssdp.pkts;
		allbytes += ssdp.bytes;
		
		printf("=\tSSDP TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", ssdp.pkts, (double)((ssdp.pkts*100.0)/ippkts), ssdp.bytes ,(double)((ssdp.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&ssdp.lock);

		pthread_mutex_lock(&ucp.lock);
		
		allpkts += ucp.pkts;
		allbytes += ucp.bytes;
		
		printf("=\tUCP TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", ucp.pkts, (double)((ucp.pkts*100.0)/ippkts), ucp.bytes ,(double)((ucp.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&ucp.lock);

		pthread_mutex_lock(&who.lock);
		
		allpkts += who.pkts;
		allbytes += who.bytes;
		
		printf("=\tWHO TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", who.pkts, (double)((who.pkts*100.0)/ippkts), who.bytes ,(double)((who.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&who.lock);

		pthread_mutex_lock(&xdmcp.lock);
		
		allpkts += xdmcp.pkts;
		allbytes += xdmcp.bytes;
		
		printf("=\tXDMCP TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", xdmcp.pkts, (double)((xdmcp.pkts*100.0)/ippkts), xdmcp.bytes ,(double)((xdmcp.bytes*100.0)/ipbytes));

		pthread_mutex_unlock(&xdmcp.lock);

		printf("=\n=\tOTHER TRAFFIC\t\t\t:\t%d  (%.3lf%%) pkts %d (%.3lf%%) bytes\n", ippkts - allpkts, (double)(((ippkts - allpkts)*100.0)/ippkts), ipbytes - allbytes ,(double)(((ipbytes - allbytes)*100.0)/ipbytes));

		printf("================================================================================\n\n");

	}

	mapi_close_flow(fd);

	return 1;
}

static char usgtxt[] = "\
%s: tracker: Network Traffic Classification tool using MAPI.\n\
Usage: %s [-h] \n\
       %s [-h] [-r file]\n\
  -h   this page\n\
  -r   read packets from file\n\
";

void usage() {
	fprintf(stderr, usgtxt, progname, progname, progname);
	exit(1);
}

void panic(char *fmt, ...)
{
	va_list ap;
	
	fprintf(stderr, "%s: panic: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

