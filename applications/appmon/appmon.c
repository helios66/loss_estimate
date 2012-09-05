#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>	      /* for Unix domain sockets: struct sockaddr_un */
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <rrd.h>
#include <stdarg.h>
#include "appmon.h"
#include "util.h"
#include <mapi.h>

#include "cgi_headers.h"
#include "anon_prefix_preserving.h"

// TOP includes
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../src/extraflib/topx.h"
#include "pidfile.h"

#define PIDFILE "/var/run/appmon.pid"


#define TOP_RESET_TIME 100

extern int daemon_proc;

static void terminate();
static void daemonize(void);
static void init_filepaths(void);
void my_rrd_create(char *filename, int num);
void my_rrd_update(char *, char *);
int create_cgi();
void *commthread(void *threadid);
void create_flows(char *scope);
void *process();

char *local_net;
char *user_net; 
int user_net_defined = 0;

int votes[NUMFILTERS];

int processing;
sem_t initialization_sem;

void usage(void);
void panic(char *fmt, ...);

static char *progname;

int verbose;
int RRD_verbose;
int refresh_time;
int do_anonymize;
int private;
int inif,outif;

char *MonitorName = "Monitor";

static char *rrd_filename, *cgi_filename;
static char *cgi3_filename, *cgi24_filename, *cgiweek_filename;
static char *cgimonth_filename, *cgiyear_filename;
static char *top_filename, *ptop_filename;

int main(int argc, char **argv) {
	char *scope = "eth0";

	int opt;

	void sig_chld(int);
	FILE *fp = NULL;
	verbose = RRD_verbose = 0;
	do_anonymize = 0;
	refresh_time = 10;
	private = 1;
	user_net = local_net = NULL;
	inif=-1;
	
	signal(SIGINT, terminate);
	signal(SIGQUIT, terminate);
	signal(SIGTERM, terminate);
	
	progname = strdup(argv[0]);

	while((opt = getopt(argc, argv, "dhvVpas:i:I:n:u:")) != EOF)
	{
		switch(opt)
		{
			case 'd':
				daemonize();
				break;
			case 'h':
				usage();
				break;
			case 'V':
				RRD_verbose = 1;
				break;
			case 'i':
				refresh_time = atoi(optarg);
				break;
			case 'I':
				inif = atoi(optarg);
				if(inif==0)
				  outif=1;
				else
				  outif=0;
				local_net="dummy";
				break;
			case 'n':
				MonitorName = strdup(optarg);
				break;
			case 'a':
				do_anonymize = 1;
				break;
			case 'p':
				do_anonymize = 1;
				private = 1;
				break;
			case 's':
				scope = strdup(optarg);
				break;
			case 'u':
				user_net_defined = 1;
				user_net = strdup(optarg);
				break;
			case 'v':
				verbose = 1;
				break;
			default:
				panic("missing argument to -%c\n", optopt);
		}
	}


	/* look for subnet filters */
	if(optind < argc) {
			local_net = strdup(argv[optind]);
			if (!daemon_proc)
				printf("local_net: %s\n",local_net);
	}

	init_filepaths();

	/* start processing */
	create_flows(scope);
	if((fp = fopen(rrd_filename, "r")) == NULL) {
			my_rrd_create(rrd_filename, NUMFILTERS);
	}
	else {
			fclose(fp);
	}
	
	create_cgi();
	processing = 1;

	process();	

    return 0;
}


void create_flows(char *scope) {

	int i;
	char *remote_net;
	char tmpstr_in[2048];
	char tmpstr_out[2048];
	char tmpstr[100];

	if (user_net_defined) {
		remote_net = user_net;
		if (!daemon_proc)
			printf("remote net: %s\n", remote_net);
	}
	else if (local_net) {
		remote_net = malloc(MAXLINE);
		snprintf(remote_net, MAXLINE, "not %s", local_net);
		if (!daemon_proc)
			printf("remote net: %s\n", remote_net);
	}


	for (i=0; i<NUMFILTERS; i++) {
		
		if (filter[i].state == INACTIVE)
			continue;

	    if ((filter[i].fd_in = mapi_create_flow(scope)) < 0)
    	    err_quit("Could not create flow in");
	    if ((filter[i].fd_out = mapi_create_flow(scope)) < 0)
    	    err_quit("Could not create flow out");

		if (user_net_defined) {
			sprintf(tmpstr, "(ip and net %s) or (vlan and net %s)", user_net, user_net);
			if (mapi_apply_function(filter[i].fd_in, "BPF_FILTER", tmpstr) < 0)
				err_quit("apply tracker BPF ip");
			if (mapi_apply_function(filter[i].fd_out, "BPF_FILTER", tmpstr) < 0)
				err_quit("apply tracker BPF ip");
		}


		/* only for trackers */
		if (filter[i].type == F_TRACKER) {
			if (mapi_apply_function(filter[i].fd_in, "BPF_FILTER", "(ip and (tcp or udp)) or (vlan and (tcp or udp))") < 0)
				err_quit("apply tracker BPF ip");
			if (mapi_apply_function(filter[i].fd_out, "BPF_FILTER", "(ip and (tcp or udp)) or (vlan and (tcp or udp))") < 0)
				err_quit("apply tracker BPF ip");
			if (mapi_apply_function(filter[i].fd_in, filter[i].f) < 0)
				err_quit("apply in tracker %s", filter[i].name);
			if (mapi_apply_function(filter[i].fd_out, filter[i].f) < 0)
				err_quit("apply out tracker %s", filter[i].name);
		}

		if ((filter[i].type == F_BPF) &&(filter[i].f != NULL)) {  // second check needed for "other"
			/* incoming traffic: remote -> local */
			if(local_net) {
					snprintf(tmpstr_in, 2048, "(ip and src net %s and dst net %s and %s) or (vlan and src net %s and dst net %s and %s)",
									remote_net, local_net, filter[i].f, remote_net, local_net, filter[i].f);
					/* outgoing traffic: local -> remote */
					snprintf(tmpstr_out, 2048, "(ip and src net %s and dst net %s and %s) or (vlan and src net %s and dst net %s and %s)",
									local_net, remote_net, filter[i].f, local_net, remote_net, filter[i].f);
			}
			else {
					snprintf(tmpstr_in, 2048, "(ip and %s) or (vlan and %s)",
									filter[i].f, filter[i].f);
					/* outgoing traffic: local -> remote */
					snprintf(tmpstr_out, 2048, "(ip and %s) or (vlan and %s)",
									filter[i].f, filter[i].f);
			}
			
			if(inif!=-1) {
			  if(mapi_apply_function(filter[i].fd_in,"INTERFACE",inif)<0)
			    err_quit("apply INTERFACE in");
			  if(mapi_apply_function(filter[i].fd_out,"INTERFACE",outif)<0)
			    err_quit("apply INTERFACE out");
			  snprintf(tmpstr_in,2048,"(ip or vlan) and %s",filter[i].f);
			  snprintf(tmpstr_out,2048,"(ip or vlan) and %s",filter[i].f);
			}
			if (mapi_apply_function(filter[i].fd_in, "BPF_FILTER", tmpstr_in) < 0)
					err_quit("apply BPF in");
			if (mapi_apply_function(filter[i].fd_out, "BPF_FILTER", tmpstr_out) < 0)
					err_quit("apply BPF out");
		}
		else {
			if(local_net) {
				/* incoming traffic: remote -> local */
				snprintf(tmpstr_in, 2048, "(ip and src net %s and dst net %s) or (vlan and src net %s and dst net %s)",
						remote_net, local_net, remote_net, local_net);
				/* outgoing traffic: local -> remote */
				snprintf(tmpstr_out, 2048, "(ip and src net %s and dst net %s) or (vlan and src net %s and dst net %s)",
						local_net, remote_net, local_net, remote_net);

				if(inif!=-1) {
				  if(mapi_apply_function(filter[i].fd_in,"INTERFACE",inif)<0)
				    err_quit("apply INTERFACE in");
				  if(mapi_apply_function(filter[i].fd_out,"INTERFACE",outif)<0)
				    err_quit("apply INTERFACE out");
				  snprintf(tmpstr_in,2048,"ip or vlan");
				  snprintf(tmpstr_out,2048,"ip or vlan");
				} 

				if (mapi_apply_function(filter[i].fd_in, "BPF_FILTER", tmpstr_in) < 0)
						err_quit("apply BPF in");
				if (mapi_apply_function(filter[i].fd_out, "BPF_FILTER", tmpstr_out) < 0)
						err_quit("apply BPF out");
			}
		}

	    if ((filter[i].fid_in = mapi_apply_function(filter[i].fd_in, "BYTE_COUNTER")) < 0)
        	err_quit("apply BYTE_COUNTER in\n");
	    if ((filter[i].fid_out = mapi_apply_function(filter[i].fd_out, "BYTE_COUNTER")) < 0)
        	err_quit("apply BYTE_COUNTER out\n");

	    // TOP FUNCTIONS
		if((filter[i].top_in = mapi_apply_function(filter[i].fd_in, "TOP", 10, TOPX_IP, TOPX_IP_DSTIP, SORT_BY_BYTES, TOP_RESET_TIME)) < 0)
		    err_quit("apply TOP DST_IP in\n");
		if((filter[i].top_out = mapi_apply_function(filter[i].fd_out, "TOP", 10, TOPX_IP, TOPX_IP_SRCIP, SORT_BY_BYTES, TOP_RESET_TIME)) < 0)
		    err_quit("apply TOP SRC_IP out\n");

	    if(mapi_connect(filter[i].fd_in) < 0)
        	err_quit("connect in\n");
	    if(mapi_connect(filter[i].fd_out) < 0)
        	err_quit("connect out\n");
	}
	if (!user_net_defined)
		free(remote_net);
}

static char top_page[] = "\
<html>\n<head>\n\
<style type=\"text/css\">\
<!--\
.style1 {font-family: Verdana, Arial, Helvetica, sans-serif}\
.style6 {color: #000000}\
.style7 {color: #CCCCCC}\
.style8 {color: #00CC00}\
.style9 {font-size: xx-small}\
-->\
</style>\
<META Http-Equiv=\"Cache-Control\" Content=\"no-cache\">\n\
<META Http-Equiv=\"Pragma\" Content=\"no-cache\">\n\
<META Http-Equiv=\"Expires\" Content=\"0\">\n\
<META Http-Equiv=\"Refresh\" Content=\"10;url=./%s\">\
</head>\n<body><div class=style1>\n";

struct top_clients_t {
    unsigned int tracker_id;
    char *tracker_name;
    unsigned int ip;
    int tracker_no;
    double speed;
};

int compare(const void *a, const void *b) 
{
    struct top_clients_t *a_d = (struct top_clients_t *)a;
    struct top_clients_t *b_d = (struct top_clients_t*)b;

    if(a_d->speed > b_d->speed)
	return -1;
    else
	return 1;
}

void sort_top(struct top_clients_t *top_res, unsigned int total) 
{
	qsort(top_res, total, sizeof(struct top_clients_t), compare);

}

char *anonimize_ip(struct in_addr ip)
{
	char *ipc = inet_ntoa(ip);
	char *temp = NULL;

	if(do_anonymize == 1) {
		temp = strrchr(ipc, '.');
		temp++;
		
		while(*temp != '\0') {
			*temp = 'X';
			temp++;
		}
	}

	return ipc;
}

void *process() {
	
	struct stats_t {
		unsigned long long prev_bytes_in;
		unsigned long long prev_bytes_out;
		unsigned long long prev_timestamp_in;
		unsigned long long prev_timestamp_out;
		unsigned long long top_prev_bytes_in;
		unsigned long long top_prev_bytes_out;
		unsigned long long top_prev_timestamp_in;
		unsigned long long top_prev_timestamp_out;
	};
	
	unsigned long long bytes_in;
	unsigned long long bytes_out;
	unsigned long long timestamp_in;
	unsigned long long timestamp_out;
	
	struct stats_t stats[NUMFILTERS] = {{0,0,0,0,0,0,0,0}};

	mapi_results_t *dres;
	char rrd_record[1024], *p;
	unsigned i;
	double speed;
	char top_page_buf[1024];
	char ptop_page_buf[1024];

	// TOP vars
	unsigned int times = 0;
	unsigned int j = 0, *cnt = NULL;
	struct topx_result *tmp;
	FILE *fp, *pfp;
	struct top_clients_t in_top_clients[NUMFILTERS*10];
	struct top_clients_t out_top_clients[NUMFILTERS*10];
	struct top_clients_t ip_in_top_clients[10], ip_out_top_clients[10];
	unsigned int in_top_cnt;
	unsigned int out_top_cnt;
	unsigned int result_time = 0;
	unsigned int out_diff_time = 0;
	
	while (processing) {
		
		sleep(refresh_time);
		in_top_cnt = out_top_cnt = 0;
		bzero(in_top_clients, NUMFILTERS * 10 * sizeof(struct top_clients_t));
		bzero(out_top_clients, NUMFILTERS * 10 * sizeof(struct top_clients_t));

		times++;
		p = rrd_record;
		p += snprintf(rrd_record, 16, "%u", (unsigned int)time(0));
		 
		for (i=0; i<NUMFILTERS; i++) {

			if (filter[i].state == INACTIVE)
				continue;

			/* read results */
			dres = mapi_read_results(filter[i].fd_in, filter[i].fid_in);
			bytes_in = *((unsigned long long*)dres[0].res);
			timestamp_in = dres[0].ts;
			dres = mapi_read_results(filter[i].fd_out, filter[i].fid_out);
			bytes_out = *((unsigned long long*)dres[0].res);
			timestamp_out = dres[0].ts;
			
			/* compute stats */
			speed = (bytes_in-stats[i].prev_bytes_in)*8 / (float)(timestamp_in - stats[i].prev_timestamp_in);
			p += snprintf(p, 16, ":%f", speed);
			speed = (bytes_out-stats[i].prev_bytes_out)*8 / (float)(timestamp_out - stats[i].prev_timestamp_out);
			
			p += snprintf(p, 16, ":-%f", speed);

			/* store current values */
			stats[i].prev_bytes_in = bytes_in;
			stats[i].prev_bytes_out = bytes_out;
			stats[i].prev_timestamp_in = timestamp_in;
			stats[i].prev_timestamp_out = timestamp_out;
			
			
			//if((times % 5) == 1 ) { 
			    dres=mapi_read_results(filter[i].fd_in,filter[i].top_in);

			    cnt = ((unsigned int*)dres[0].res);
			    timestamp_in = dres[0].ts;
    			    result_time = dres[0].ts;
			    
			    tmp=(struct topx_result *)(cnt+1);			
			   
			    for(j=0;j<(*cnt);j++) {
					if(i == 0) {
						ip_in_top_clients[j].ip=tmp->value;
						ip_in_top_clients[j].tracker_name=filter[i].name;
						ip_in_top_clients[j].tracker_no=i;
						if(tmp->bytecount == 0) {
							ip_in_top_clients[j].speed = 0.0;
						}
						else if((result_time - tmp->last_rst_secs) == 0) {
							ip_in_top_clients[j].speed = 0.0;
						}
						else {
							ip_in_top_clients[j].speed = ((tmp->bytecount * 8.0)/1024.0) /((result_time - tmp->last_rst_secs)/1000000.0);
						}
					}
					else {
						in_top_clients[in_top_cnt].ip=tmp->value;
						in_top_clients[in_top_cnt].tracker_name=filter[i].name;
						in_top_clients[in_top_cnt].tracker_no=i;
						if(tmp->bytecount == 0) {
								in_top_clients[in_top_cnt].speed = 0.0;
						}
						else if((result_time - tmp->last_rst_secs) == 0) {
							in_top_clients[in_top_cnt].speed = 0.0;
						}
						else {
								in_top_clients[in_top_cnt].speed = ((tmp->bytecount * 8.0)/1024.0) /((result_time - tmp->last_rst_secs)/1000000.0);
						}
						in_top_cnt++;
					}	
					tmp++;
				}
			   
		    
			    dres=mapi_read_results(filter[i].fd_out,filter[i].top_out);
			    result_time = dres[0].ts;
			    cnt = ((unsigned int*)dres[0].res);
			    timestamp_out = dres[0].ts;
			    
			    tmp=(struct topx_result *)(cnt+1);			
			    
			    out_diff_time = result_time/1000000 - tmp->last_rst_secs/1000000; 

			    for(j=0;j<(*cnt);j++) {
						if(i == 0) {
							ip_out_top_clients[j].ip=tmp->value;
							ip_out_top_clients[j].tracker_name=filter[i].name;
							ip_out_top_clients[j].tracker_no=i;
							if(tmp->bytecount == 0) {
									ip_out_top_clients[j].speed = 0.0;
							}
							else if((result_time - tmp->last_rst_secs) == 0) {
									ip_out_top_clients[j].speed = 0.0;
							}
							else {
								ip_out_top_clients[j].speed = ((tmp->bytecount * 8.0)/1024.0) /((result_time - tmp->last_rst_secs)/1000000.0);
							}
						}
						else {	   
							out_top_clients[out_top_cnt].ip=tmp->value;
							out_top_clients[out_top_cnt].tracker_name=filter[i].name;
							out_top_clients[out_top_cnt].tracker_no=i;
							if(tmp->bytecount == 0) {
								out_top_clients[out_top_cnt].speed = 0.0;
							}
							else if((result_time - tmp->last_rst_secs) == 0) {
								out_top_clients[out_top_cnt].speed = 0.0;
							}
							else {
								out_top_clients[out_top_cnt].speed = ((tmp->bytecount * 8.0)/1024.0)/((result_time - tmp->last_rst_secs)/1000000.0);
							}
							out_top_cnt++;
						}
						tmp++;
				}
		}

		my_rrd_update(rrd_filename, rrd_record);

//		if((times % 5) == 1) {
		    
		    sort_top(in_top_clients, in_top_cnt);
		    sort_top(out_top_clients, out_top_cnt);
		  
		    fp = fopen(top_filename, "w");
		   
		    sprintf(top_page_buf, top_page, top_filename);

		    fprintf(fp, "%s", top_page_buf);
		   
				if(private) {
					fprintf(fp, "<div class=\"style1\"><p align=center><a href=private/%s>Private Section Non-Anonymized</a></p>", ptop_filename);
				}
				
		    fprintf(fp, "<center><table border=\"0\" width=75\% bgcolor=\"#999999\" cellpadding=\"1\" cellspacing=\"1\"> \n");
		    fprintf(fp, "\n<tr bgcolor=\"#ffffff\"><th colspan=3>INCOMING TRAFFIC</th></tr>\n");
		    fprintf(fp, "<tr bgcolor=\"#ffffff\"><th>IP</th><th>Protocol</th><th>Traffic</th></tr>\n"); 
		 
		    if(private) {
					pfp = fopen(ptop_filename, "w");

					sprintf(ptop_page_buf, top_page, ptop_filename);
					fprintf(pfp, "%s", ptop_page_buf);
					
					fprintf(pfp, "<div class=\"style1\"><center>\n");
		    	fprintf(pfp, "<table border=0 width=\"75\%\" bgcolor=\"#999999\" cellpadding=\"1\" cellspacing=\"1\" >\n");
					fprintf(pfp, "\n<tr bgcolor=\"#ffffff\"><th colspan=3>INCOMING TRAFFIC</th></tr>\n");
					fprintf(pfp, "<tr bgcolor=\"#ffffff\"><th>IP</th><th>Protocol</th><th>Traffic</th></tr>\n"); 
				}

		    for(i = 0; i < 10 && i < in_top_cnt; i++) {
					struct in_addr ip;
					struct in_addr anon_ip;

					ip.s_addr = (unsigned long int)in_top_clients[i].ip;
				
					fprintf(fp, "<tr bgcolor=\"#ffffff\">\n");

					if(do_anonymize) {
						prefix_preserving_anonymize_field(&(in_top_clients[i].ip));
						anon_ip.s_addr = in_top_clients[i].ip;
						fprintf(fp, "<td align=left>%s</td>\n", inet_ntoa(anon_ip));
					}
					else {
						fprintf(fp, "<td align=left>%s</td>\n", inet_ntoa(ip));
					}
					
					fprintf(fp, "<td align=center bgcolor=\"%s\"> %s </td>\n",filter[in_top_clients[i].tracker_no].color,in_top_clients[i].tracker_name);
					fprintf(fp, "<td align=right>%.2lf Kbps</td>\n", in_top_clients[i].speed);
					fprintf(fp, "</tr>\n");
					
					if(private) {
						fprintf(pfp, "<tr bgcolor=\"#ffffff\">\n");
						fprintf(pfp, "<td align=left>%s</td>\n", inet_ntoa(ip));
						fprintf(pfp, "<td align=center bgcolor=\"%s\"> %s </td>\n",filter[in_top_clients[i].tracker_no].color,in_top_clients[i].tracker_name);
						fprintf(pfp, "<td align=right>%.2lf Kbps</td>\n", in_top_clients[i].speed);
						fprintf(pfp, "</tr>\n");
					}

		    }
		    
		    fprintf(fp, "</table></center>\n");
		   	
		    fprintf(fp, "<P>\n");

		    fprintf(fp, "<center>\n");
		    fprintf(fp, "<table border=0 width=75\% bgcolor=\"#999999\" cellpadding=\"1\" cellspacing=\"1\" >\n");
		    fprintf(fp, "\n<tr bgcolor=\"#ffffff\"><th colspan=3>OUTGOING TRAFFIC</th></tr>\n");
		    fprintf(fp, "<tr bgcolor=\"#ffffff\"><th>IP</th><th>Protocol</th><th>Traffic</th></tr>\n");
		   
				if(private) {
					fprintf(pfp, "</table></center>\n");
					
					fprintf(pfp, "<P>\n");
					
					fprintf(pfp, "<center>\n");
		    	fprintf(pfp, "<table border=0 width=75\% bgcolor=\"#999999\" cellpadding=\"1\" cellspacing=\"1\" >\n");
					fprintf(pfp, "\n<tr bgcolor=\"#ffffff\"><th colspan=3>OUTGOING TRAFFIC</th></tr>\n");
					fprintf(pfp, "<tr bgcolor=\"#ffffff\"><th>IP</th><th>Protocol</th><th>Traffic</th></tr>\n");
				}

		    for(i = 0; i < 10 && i < out_top_cnt; i++) {
					struct in_addr ip;
					struct in_addr anon_ip;
					fprintf(fp, "<tr bgcolor=\"#ffffff\">\n");
					ip.s_addr = (unsigned long int)out_top_clients[i].ip;
					if(do_anonymize) {
						prefix_preserving_anonymize_field(&(out_top_clients[i].ip));
						anon_ip.s_addr = out_top_clients[i].ip;
						fprintf(fp, "<td align=left>%s</td>\n", inet_ntoa(anon_ip));
					}
					else {
						fprintf(fp, "<td align=left>%s</td>\n", inet_ntoa(ip));
					}

					fprintf(fp, "<td align=center bgcolor=\"%s\"> %s </td>\n", filter[out_top_clients[i].tracker_no].color,out_top_clients[i].tracker_name);
					fprintf(fp, "<td align=right>%.2lf Kbps</td>\n", out_top_clients[i].speed);
					
					fprintf(fp, "</tr>\n");
					
					if(private) {
						fprintf(pfp, "<tr bgcolor=\"#ffffff\">\n");
						fprintf(pfp, "<td align=left>%s</td>\n", inet_ntoa(ip));
						fprintf(pfp, "<td align=center bgcolor=\"%s\"> %s </td>\n",filter[out_top_clients[i].tracker_no].color,out_top_clients[i].tracker_name);
						fprintf(pfp, "<td align=right>%.2lf Kbps</td>\n", out_top_clients[i].speed);
						fprintf(pfp, "</tr>\n");
					}
				}

		    fprintf(fp, "</table></center>\n");

		    fprintf(fp, "<P>\n");

		    fprintf(fp, "<center>\n");
		    fprintf(fp, "<table border=0 width=75\% bgcolor=\"#999999\" cellpadding=\"1\" cellspacing=\"1\" >\n");
		    fprintf(fp, "\n<tr bgcolor=\"#ffffff\"> <th colspan=4>TOTAL TRAFFIC</th></tr>\n");
		    fprintf(fp, "\n<tr bgcolor=\"#ffffff\"> <th colspan=2>INCOMING TRAFFIC</th> <th colspan=2>OUTGOING TRAFFIC</th></tr>\n");
		    fprintf(fp, "<tr bgcolor=\"#ffffff\"><th>IP</th><th>Traffic</th><th>IP</th><th>Traffic</th></tr>\n"); 
		
				if(private) {
					fprintf(pfp, "</table></center>\n");
					
					fprintf(pfp, "<P>\n");
					
					fprintf(pfp, "<center>\n");
		    	fprintf(pfp, "<table border=0 width=75\% bgcolor=\"#999999\" cellpadding=\"1\" cellspacing=\"1\" >\n");
					fprintf(pfp, "\n<tr bgcolor=\"#ffffff\"> <th colspan=4>TOTAL TRAFFIC</th></tr>\n");
					fprintf(pfp, "\n<tr bgcolor=\"#ffffff\"> <th colspan=2>INCOMING TRAFFIC</th> <th colspan=2>OUTGOING TRAFFIC</th></tr>\n");
					fprintf(pfp, "<tr bgcolor=\"#ffffff\"><th>IP</th><th>Traffic</th><th>IP</th><th>Traffic</th></tr>\n"); 
				}

		    for(i = 0; i < 5;i++) {
					struct in_addr ip;
					struct in_addr anon_ip;

					fprintf(fp, "<tr bgcolor=\"#ffffff\">\n");

					if(private) {
						fprintf(pfp, "<tr bgcolor=\"#ffffff\">\n");
					}
					// IN
					ip.s_addr = (unsigned long int)ip_in_top_clients[i].ip;
					if(do_anonymize) {
						prefix_preserving_anonymize_field(&(ip_in_top_clients[i].ip));
						anon_ip.s_addr = ip_in_top_clients[i].ip;
						fprintf(fp, "<td align=left>%s</td>\n", inet_ntoa(anon_ip));
					}
					else {
						fprintf(fp, "<td align=left>%s</td>\n", inet_ntoa(ip));
					}
					fprintf(fp, "<td align=right>%.2lf Kbps</td>\n", ip_in_top_clients[i].speed);
				
					if(private) {
						fprintf(pfp, "<td align=left>%s</td>\n", inet_ntoa(ip));
						fprintf(pfp, "<td align=right>%.2lf Kbps</td>\n", ip_in_top_clients[i].speed);
					}

					// OUT
					ip.s_addr = (unsigned long int)ip_out_top_clients[i].ip;

					if(do_anonymize) {
						prefix_preserving_anonymize_field(&(ip_out_top_clients[i].ip));
						anon_ip.s_addr = ip_out_top_clients[i].ip;
						fprintf(fp, "<td align=left>%s</td>\n", inet_ntoa(anon_ip));
					}
					else {
						fprintf(fp, "<td align=left>%s</td>\n", inet_ntoa(ip));
					}

					fprintf(fp, "<td align=right>%.2lf Kbps</td>\n", ip_out_top_clients[i].speed);
					
					fprintf(fp, "</tr>\n");

					if(private) {
						fprintf(pfp, "<td align=left>%s</td>\n", inet_ntoa(ip));
						fprintf(pfp, "<td align=right>%.2lf Kbps</td>\n", ip_out_top_clients[i].speed);
						fprintf(pfp, "</tr>\n");
					}
		    }

		    fprintf(fp, "</table></center>\n");

		    fprintf(fp, "</div></body></html>");
		    fflush(fp);
		    fclose(fp);
				
				if(private) {
					fprintf(pfp, "</table></center>\n");
					
					fprintf(pfp, "</div></body></html>");
					fflush(pfp);
					fclose(pfp);
				}
//		}
	}

	return 0;
}

void print_common(FILE *fp, char *cwd)
{
	int i = 0;

//	if (user_net_defined)	
		fprintf(fp, "--title \"Application Traffic Breakdown:  %s\"\n", MonitorName);
//	else
	//	fprintf(fp, "--title \"Traffic Breakdown:  %s\"\n", local_net);

	for(i=0; i<NUMFILTERS; ++i) {
		if (filter[i].state == INACTIVE)
			continue;
		fprintf(fp, "    DEF:flow%d_in=%s/%s:flow%d_in:AVERAGE\n", i, cwd, rrd_filename, i);
		fprintf(fp, "    DEF:flow%d_out=%s/%s:flow%d_out:AVERAGE\n", i, cwd, rrd_filename, i);
		if(RRD_verbose) {

			fprintf(fp, "    VDEF:flow%d_in_last=flow%d_in,LAST\n", i, i);
			fprintf(fp, "    CDEF:flow%d_out_lastc=flow%d_out,-1,*\n", i, i);
			fprintf(fp, "    VDEF:flow%d_out_last=flow%d_out_lastc,LAST\n", i, i);

			if(i > 0) {
				fprintf(fp, "		CDEF:flow%d_in_per=flow%d_in,100,*,flow0_in,/\n", i, i);
				fprintf(fp, "		CDEF:flow%d_out_per=flow%d_out,100,*,flow0_out,/\n", i, i);

				fprintf(fp, "    VDEF:flow%d_in_last_per=flow%d_in_per,LAST\n", i, i);
				fprintf(fp, "    VDEF:flow%d_out_last_per=flow%d_out_per,LAST\n", i, i);
			}
		}
	}

	if(RRD_verbose) {
			fprintf(fp, "COMMENT:\"\\t\\t\\t\\t\\t\\t\\tIn\\t\\t\\t\\tOut\\n\"\n");
	}
	/* in */
	if (filter[0].state == ACTIVE) {
		if(RRD_verbose) {
				fprintf(fp, "COMMENT:\"\\t\"\n");
		}
		fprintf(fp, "    AREA:flow%d_in#%s::\n", 0, "EEEEEE");
		if(!RRD_verbose) {
			fprintf(fp, "    LINE:flow%d_in#%s:\"%s\":\n", 0, filter[0].color, filter[0].name);
		}
		else {
				char name[15];
				int k = 0;
				for(k = 0; filter[0].name[k] != '\0'; k++) {
						name[k] = filter[0].name[k];
				}
				for(;k < 15; k++) {
						name[k] = ' ';
				}
				name[k] = '\0';
				
				fprintf(fp, "    LINE:flow%d_in#%s:\"%s\":\n", 0, filter[0].color, name);
				fprintf(fp, "GPRINT:flow%d_in_last:\"%%6.2lf %%Sbps\\t\\t\"\n", 0);
				fprintf(fp, "GPRINT:flow%d_out_last:\"\\t\\t%%6.2lf %%Sbps\\n\"\n", 0);

		}
	}
	fprintf(fp, "    LINE:0\n");
	for (i=1; i<NUMFILTERS; ++i)
		if (filter[i].state == ACTIVE) {
			if(RRD_verbose) {
				fprintf(fp, "COMMENT:\"\\t\"\n");
			}
			if(!RRD_verbose) {
				fprintf(fp, "    AREA:flow%d_in#%s:\"%s\":STACK\n", i, filter[i].color, filter[i].name);
			}
			else {
				char name[15];
				int k = 0;
				for(k = 0; filter[i].name[k] != '\0'; k++) {
						name[k] = filter[i].name[k];
				}
				for(;k < 15; k++) {
						name[k] = ' ';
				}
				name[k] = '\0';

				fprintf(fp, "    AREA:flow%d_in#%s:\"%s\":STACK\n", i, filter[i].color, name);
				fprintf(fp, "GPRINT:flow%d_in_last:\"%%6.2lf %%Sbps\"\n", i);
				fprintf(fp, "GPRINT:flow%d_in_last_per:\"(%%6.2lf %%%%)\"\n", i);
				fprintf(fp, "GPRINT:flow%d_out_last:\"\\t%%6.2lf %%Sbps\"\n", i);
				fprintf(fp, "GPRINT:flow%d_out_last_per:\"(%%6.2lf %%%%)\\n\"\n", i);
					
			}
		}
		

	/* out */
	if (filter[0].state == ACTIVE) {
		fprintf(fp, "    AREA:flow%d_out#%s::\n", 0, "EEEEEE");
		fprintf(fp, "    LINE:flow%d_out#%s::\n", 0, filter[0].color);
	}
	fprintf(fp, "    LINE:0\n");
	for (i=1; i<NUMFILTERS; ++i)
		if (filter[i].state == ACTIVE) {
			fprintf(fp, "    AREA:flow%d_out#%s::STACK\n", i, filter[i].color);
		}
	
	fprintf(fp, "    LINE:0#000000\n");

	fprintf(fp, "COMMENT:\"\\n\"\n");
	fprintf(fp, "COMMENT:\"\\t\\tPOWERED by LOBSTER IST Project (www.ist-lobster.org)\"\n");

	fprintf(fp, ">\n</P>\n");

	fprintf(fp,"</center>\n");
	
	fprintf(fp, "</BODY>\n</HTML>\n");

}

int create_cgi() {
	FILE *fp;
	char cwd[512];

	// HOUR
	if((fp = fopen(cgi_filename,"w")) == NULL)
		err_quit("Can't create output file");
	chmod(cgi_filename, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	getcwd(cwd, 512);	//FIXME

	fprintf(fp, "%s", cgiHead);
	fprintf(fp, "%s", MonitorName);
	fprintf(fp, "%s", cgiHead2);
	fprintf(fp, IMAGE_NAME, "appmon.png", RRD_ATRS);
	fprintf(fp, cgiHead3, "3600s");
	
	print_common(fp, cwd);

	fclose(fp);
		
	// 3 HOURs
	if((fp = fopen(cgi3_filename,"w")) == NULL)
		err_quit("Can't create output file");
	chmod(cgi3_filename, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	getcwd(cwd, 512);	//FIXME

	fprintf(fp, "%s", cgiHead);
	fprintf(fp, "%s", MonitorName);
	fprintf(fp, "%s", cgiHead2);
	fprintf(fp, IMAGE_NAME, "appmon3hours.png", RRD_ATRS);
	fprintf(fp, cgiHead3, "3h");

	print_common(fp, cwd);

	fclose(fp);

	// 1 DAY
	if((fp = fopen(cgi24_filename,"w")) == NULL)
		err_quit("Can't create output file");
	chmod(cgi24_filename, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	getcwd(cwd, 512);	//FIXME

	fprintf(fp, "%s", cgiHead);
	fprintf(fp, "%s", MonitorName);
	fprintf(fp, "%s", cgiHead2);
	fprintf(fp, IMAGE_NAME, "appmonday.png", RRD_ATRS);
	fprintf(fp, cgiHead3, "24h");

	print_common(fp, cwd);

	fclose(fp);

	// 1 WEEK
	if((fp = fopen(cgiweek_filename,"w")) == NULL)
		err_quit("Can't create output file");
	chmod(cgiweek_filename, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	getcwd(cwd, 512);	//FIXME

	fprintf(fp, "%s", cgiHead);
	fprintf(fp, "%s", MonitorName);
	fprintf(fp, "%s", cgiHead2);
	fprintf(fp, IMAGE_NAME, "appmonweek.png", RRD_ATRS);
	fprintf(fp, cgiHead3, "7d");

	print_common(fp, cwd);

	fclose(fp);

	// 1 MONTH
	if((fp = fopen(cgimonth_filename,"w")) == NULL)
		err_quit("Can't create output file");
	chmod(cgimonth_filename, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	getcwd(cwd, 512);	//FIXME

	fprintf(fp, "%s", cgiHead);
	fprintf(fp, "%s", MonitorName);
	fprintf(fp, "%s", cgiHead2);
	fprintf(fp, IMAGE_NAME, "appmonmonth.png", RRD_ATRS);
	fprintf(fp, cgiHead3, "31d");

	print_common(fp, cwd);

	fclose(fp);

	// 1 YEAR
	if((fp = fopen(cgiyear_filename,"w")) == NULL)
		err_quit("Can't create output file");
	chmod(cgiyear_filename, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	getcwd(cwd, 512);	//FIXME

	fprintf(fp, "%s", cgiHead);
	fprintf(fp, "%s", MonitorName);
	fprintf(fp, "%s", cgiHead2);
	fprintf(fp, IMAGE_NAME, "appmonyear.png", RRD_ATRS);
	fprintf(fp, cgiHead3, "1year");

	print_common(fp, cwd);

	fclose(fp);

	
	return 0;
}

void my_rrd_create(char *filename, int num) {
	int ret, i;
	char start[20];
	char tmp[64];
	char **argv;
	char temp[1024];

	int num_active = 0;

	argv = malloc((13+num*2)*sizeof(char *));
	argv[0] = strdup("create");
	argv[1] = strdup("--start");
	snprintf(start, 20, "%u", (unsigned int)time(0));
	argv[2] = start;
	argv[3] = strdup("--step");
	sprintf(temp, "%d", refresh_time);
	argv[4] = strdup(temp);
	argv[5] = filename;

	for (i=0; i<num; i++) { // loop through all filters (we don't know which are active)
		if (filter[i].state == INACTIVE)
			continue;
		if (!daemon_proc)
			printf("::RRD:: creating records for %d %s\n", i, filter[i].name);
		snprintf(tmp, 64, "DS:flow%d_in:GAUGE:600:-1000:1000", i);
		argv[6+num_active++] = strdup(tmp);
		snprintf(tmp, 64, "DS:flow%d_out:GAUGE:600:-1000:1000", i);
		argv[6+num_active++] = strdup(tmp);
	}
	if (!daemon_proc)
		printf("::RRD:: created %d records\n", num_active);
	argv[6+num_active] = strdup("RRA:AVERAGE:0.5:1:10000"); /* 1 hour */
	argv[6+num_active+1] = strdup("RRA:AVERAGE:0.5:6:360"); // 3 hours
	argv[6+num_active+2] = strdup("RRA:AVERAGE:0.5:30:360"); // 1 day
	argv[6+num_active+3] = strdup("RRA:AVERAGE:0.5:180:360"); // 1 week
	argv[6+num_active+4] = strdup("RRA:AVERAGE:0.5:720:372"); // 1 month
	argv[6+num_active+5] = strdup("RRA:AVERAGE:0.5:8760:360"); // 1 year
	argv[6+num_active+6] = NULL;

	optind = opterr = 0; 				/* reset optind/opterr */
	ret = rrd_create(13+num_active-2,argv); 		/* try to create rrd */
	//printf("rrd_create: %d\n", ret); /* print result */
	if(rrd_test_error()) { 				/* look for errors */
		if (daemon_proc)
			printf("rrd_create: %s\n",rrd_get_error());
		else
			syslog(LOG_ERR, "rrd_create: %s\n",rrd_get_error());
	   	rrd_clear_error();
	}
	//TODO free strdups
//	free(argv[0]);
//	free(argv[1]);
//	free(argv[3]);
//	free(argv[4]);
//	free(argv);
}

void my_rrd_update(char *filename, char *data) {
	int ret, argc = 3;
	char *argv[] = { 					/* update template */
		"update",
		NULL, 								/* 3 filename */
		NULL, 								/* 4 data */
		NULL
	};
	
	argv[1] = filename; 					/* set filename */
	argv[2] = data; 						/* set data */
	optind = opterr = 0; 				/* reset optind/opterr */
	ret = rrd_update(argc,argv); 		/* try to update rrd */
	//printf("rrd_update: %d\n", ret); /* print result */
	if(rrd_test_error()) { 				/* look for errors */
		if (daemon_proc)
			printf("rrd_create: %s\n",rrd_get_error());
		else
			syslog(LOG_ERR, "rrd_update: %s\n",rrd_get_error());
		rrd_clear_error();
	}
}

static void remove_pidfile(void)
{
	(void) remove_pid(PIDFILE);
}

static void daemonize() {

	int nullfd;

	switch (fork()) {
	case 0:
		break;
	case -1:
		err_sys ("fork() failed");
		return;		/* Not reached */
		break;
	default:
		_exit(0);
		break;
	}
	if (setsid() == -1) {
		err_sys ("setsid() failed");
		return;		/* Not reached */
	}

	setpgrp();

	switch (fork()) {
	case 0:
		break;
	case -1:
		err_sys ("fork() failed");
		return;		/* Not reached */
		break;
	default:
		_exit(0);
		break;
	}

	if (!check_pid(PIDFILE)) {
		if (write_pid(PIDFILE)) {
			(void) atexit(remove_pidfile);
		} else {
			printf("Could not write pidfile\n");
		}
	} else {
		/* A mapid already running and owning pidfile */
		printf("A mapid is already running. Leaving pidfile alone\n");
		
	}
	
	chdir("/");

	nullfd = open("/dev/null", O_RDONLY);
	dup2(nullfd, STDIN_FILENO);
	close(nullfd);
	nullfd = open("/dev/null", O_WRONLY);
	dup2(nullfd, STDOUT_FILENO);
	dup2(nullfd, STDERR_FILENO);
	close(nullfd);

	daemon_proc = 1;
}

void terminate() {
	int i;
	for (i=0; i<NUMFILTERS; i++) {
		if (filter[i].state == INACTIVE)
			continue;
    	mapi_close_flow(filter[i].fd_in);
    	mapi_close_flow(filter[i].fd_out);
	}
    exit(EXIT_SUCCESS);
}

static char *get_filepath (const char * const filename)
{
	if (filename) {
		char *buf;
		if (daemon_proc) {
			int len = strlen(APPMON_DIR) + strlen (filename) + 2;
			buf =  malloc (len);
			snprintf (buf, len, 
					 "%s/%s", APPMON_DIR, filename);
			return buf;
		} else {
			return strdup (filename);
		}
	} else {
		return strdup ("");
	}
}

static void init_filepaths (void)
{
	rrd_filename      = get_filepath (RRD_FILENAME);
	cgi_filename      = get_filepath (CGI_FILENAME);
	cgi3_filename     = get_filepath ("appmon3.cgi");
	cgi24_filename    = get_filepath ("appmon24.cgi");
	cgiweek_filename  = get_filepath ("appmonWeek.cgi");
	cgimonth_filename = get_filepath ("appmonMonth.cgi");
	cgiyear_filename  = get_filepath ("appmonYear.cgi");
	top_filename      = get_filepath (TOP_FILENAME);
	ptop_filename     = get_filepath (PTOP_FILENAME);
}

static char usgtxt[] = "\
%s: appmon: Network Traffic Classification tool using MAPI.\n\
Usage: %s [-hpav] -u <user subnet> [-n <MonitorTitle>] [-s <host:interface>] [localnet]\n\
\t-h\t\tthis page\n\
\t-d\t\trun as daemon\n\
\t-a\t\tanonymize IPs\n\
\t-p\t\tcreate private page with non anonymized IPs\n\
\t-v\t\tverbose\n\
\t-V\t\tRRD graph verbosity\n\
\t-u userSubnet\tprovide IP/Net to check\n\
\t-n monitorTitle\tprovide Monitor Title for Webpage\n\
\t-s sensor\tSensor IP and interface. Multiple sensors separated by a comma\n\
\n";

void usage() {
	fprintf(stderr, usgtxt, progname, progname, progname, progname);
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

