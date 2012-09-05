#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef  NO_MAPI
#include <nids.h>
#else
#include <mapi.h>
#endif


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in_systm.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pcap.h>

#include "options.h"
#include "stride/stride.h"
#include "ear/ear.h"
#include "report.h"
#include "ear/timer.h"

// How deep withing the flow are we going to apply stride
#define MIN(x, y) ((x < y) ? x : y)


#define int_ntoa(x)	 inet_ntoa(*((struct in_addr *)&x))

extern int errno;

static struct ear *ear;
extern struct timeval cur_time;

void terminate(int sig) {
	ear_destroy(ear);
	exit(0);
}
/*
void stride_tcp_callback(struct tcp_stream *a_tcp, void **unused)
{
	struct half_stream *hlf = &a_tcp->server;

	if (a_tcp->nids_state == NIDS_JUST_EST) {
		a_tcp->server.collect++; // we want data received by a server
		return;
	}

	if (a_tcp->nids_state == NIDS_DATA) {
		nids_discard(a_tcp, 0); // discard nothing
		if (hlf->count < config_stride_flow_depth) {
			return; // need more
		} else { // enough data
			a_tcp->server.collect--; // stop collecting
		}
	}

	// We are here after reset, close, time-out, exit, or enough data

	int data_size = MIN(hlf->count, config_stride_flow_depth); 

	if (data_size < config_stride_sled_length)
		return;
	
	//printf("Processing %d bytes with stride.\n", data_size);
	//write(2, hlf->data, data_size);
	int sled_offset = stride_process(hlf->data, data_size,
			4, config_stride_sled_length/2, config_stride_sled_length/2, 0);
	//printf("%d\n", sled_offset);
	if (sled_offset != -1) {
		report_sled(a_tcp->addr);
	}

	return;
}
*/

#ifndef NO_MAPI
void ear_tcp_callback(const struct mapipkt *mpkt)
{
	struct ear_flow_state *ptr;
	struct hdr a_hdr;
	struct iphdr *iph;
	unsigned char *p;
	struct tcphdr *th;
	int payoff, dsize;

	p = (unsigned char *)&(mpkt->ts);
	cur_time.tv_sec = *(unsigned int*)(p+4);
	cur_time.tv_usec = (unsigned int)((((double)*(unsigned int *)p)*1000000.0)/((unsigned int)(~0)));

	p = (unsigned char *)&(mpkt->pkt);
	iph = (struct iphdr *)(p + ETH_HLEN);
	th = (struct tcphdr *)(p + ETH_HLEN + iph->ihl*4);
	payoff = ETH_HLEN + iph->ihl*4 + th->doff*4;

	dsize = ntohs(iph->tot_len) - iph->ihl*4 - th->doff*4;
	
	ptr = ear_flow_state_create();

	a_hdr.saddr = iph->saddr;
	a_hdr.daddr = iph->daddr;
	a_hdr.source = ntohs(th->source);
	a_hdr.dest = ntohs(th->dest);

	if (dsize > 0) {
		ear_process(ear, &a_hdr, (p+payoff), dsize, 0, ptr);
	}

	ear_flow_state_destroy(ptr);
}
#else
void ear_tcp_callback(struct tcp_stream *a_tcp, void **ptr)
{
        int dsize, discard;
		struct hdr a_hdr;

        if (a_tcp->nids_state == NIDS_JUST_EST) {
                //printf("Tracking %s\n", flow2string(a_tcp->addr));
                a_tcp->server.collect++;
                *ptr = ear_flow_state_create();
                return;
        }

        if (a_tcp->server.count > config_flow_limit)
                dsize = config_flow_limit - a_tcp->server.offset;
        else
                dsize = a_tcp->server.count - a_tcp->server.offset;

        assert(dsize >= 0);
		
		a_hdr.source = a_tcp->addr.source;
		a_hdr.dest = a_tcp->addr.dest;
		a_hdr.saddr = a_tcp->addr.saddr;
		a_hdr.daddr = a_tcp->addr.daddr;
		cur_time = nids_last_pcap_header->ts;

        if (dsize > 0)
                ear_process(ear, &a_hdr, a_tcp->server.data, 
					dsize, a_tcp->server.offset, *ptr);

        // leave at most span-1 bytes in buffer
        discard = dsize - (ear->span - 1);
        if (discard < 0) discard = 0;
        nids_discard(a_tcp, discard);

        if (a_tcp->nids_state != NIDS_DATA // seems the stream is closing
                        || a_tcp->server.count >= config_flow_limit)
        {
                //printf("Leaving %s\n", flow2string(a_tcp->addr));
                a_tcp->server.collect--;
                ear_flow_state_destroy(*ptr);
        }
}
#endif

void param_change(struct ear *ear) {
    static int comm=-1;
    int bread=0;
    char buf[256];
    
    if (comm == -1) {
	comm = open(EARLIVE_DIR"comm", O_RDONLY | O_NONBLOCK);
	LOG("Opened fifo : %s - %d", EARLIVE_DIR"comm", comm);
	if (comm == -1) {
		perror(EARLIVE_DIR"comm");
		exit(EXIT_FAILURE);
	}
    }
    if ((bread=read(comm, buf, 256)) > 0) {
	buf[bread]='\0';
	if (sscanf(buf, "%d %d %d", &ear->span, &ear->cache->threshold,
		&ear->cache->queue_size) != 3) {
	    LOG("katastrof");
	}
	else {
	    LOG("Param Change successful : %d/%d/%d", ear->span, ear->cache->threshold, ear->cache->queue_size);
	}
    }
}

int main(int argc, char **argv)
{
#ifndef NO_MAPI
	int fd=0, fid_buf, fid_bpf;
#endif
    
	signal(SIGINT, terminate);

	get_options(argc, argv);

	ear = ear_create(config_substring_length,
			config_cache_size,
			config_target_threshold,
			config_flow_limit,
			config_select_mask,
			config_skip_nul);
	
	//add callback for param change
	ear->param_change = param_change;
	// add callbacks for reporting
	ear->report_alert = report_alert;
	ear->report_tracked = report_tracked;
	ear->report_attack = report_attack;
	ear->report_stats = report_stats;
	ear->report_summary = report_summary;

#ifndef NO_MAPI
	if (config_trace)
		fd = mapi_create_offline_flow(config_trace, MFF_PCAP);

	if (config_device)
		fd = mapi_create_flow(config_device);

	if (fd == -1)
	    exit(-1);

	LOG("Created mapi flow: %d", fd);

/*        if(mapi_authenticate(fd, "gvasil", "gvasil", "DCS"))
        {
                fprintf(stderr, "Authentication failed.\n");
                return(-1);
        }
        else
                fprintf(stderr, "Authentication successful.\n");
*/
	if (mapi_apply_function(fd, "BPF_FILTER", "tcp") == -1)
	    exit(-1);
	

	if (config_bpf)
		if ((fid_bpf=mapi_apply_function(fd, 
				"BPF_FILTER", config_bpf)) == -1)
		    exit(-1);

	if (mapi_apply_function(fd, "COOKING", config_flow_limit, 10, 1, SERVER_SIDE) == -1) 
	    exit(-1);

	if ((fid_buf=mapi_apply_function(fd, "TO_BUFFER")) == -1) 
	    exit(-1);

	LOG("Applied mapi functions: BPF_FILTER, COOKING and TO_BUFFER");

	mapi_connect(fd);

	mapi_loop(fd, fid_buf, -1, &ear_tcp_callback);

	LOG("kato apo mapi_loop");
#else
//Using libnids

	struct nids_chksum_ctl nochksumchk;

	/* disable checksum checking for all packets */
	nochksumchk.netaddr = 0;
	nochksumchk.mask = 0;
	nochksumchk.action = NIDS_DONT_CHKSUM;

	nids_register_chksum_ctl(&nochksumchk, 1);
	nids_params.n_tcp_streams=10000;
	if (config_trace)
		nids_params.filename = config_trace;
	if (config_device)
		nids_params.device = config_device;

	nids_params.pcap_filter = config_bpf;

	if (!nids_init()) {
		fprintf(stderr, "%s\n", nids_errbuf);
		exit(1);
	}

	if (config_ear_enabled) {
		nids_register_tcp(ear_tcp_callback);
	}

/*	if (config_stride_enabled) {
		nids_register_tcp(stride_tcp_callback);
		stride_init();
	}
*/
	nids_run();
#endif
	ear_destroy(ear);

	return 0;
}
