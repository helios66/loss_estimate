#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include "util.h"
#include "mapi.h"

void usage(void);
void panic(char *fmt, ...);

static char *progname;
	
static int verbose    = 0;
static int offline    = 0;
static int to_file    = 0;
static int to_count   = 0;
static int str_search = 0;
static int fullpacket = 0;

char *DEV = "/dev/dag0";

int main(int argc, char *argv[])
{
	int opt;
	int count = 0;
	char str[128];
	char *readfile = NULL;
	char *writefile = NULL;
	char *searchstring = NULL;
		
	char *cp = NULL;
	char filterbuf[4096];

	int errno;
	char errbuf[1024];

	int fd = 0;
	int fid = 0;
	int fidi = 0;
	int fidf = 0;
	int fids = 0;
	int bufid = 0;
	int cnt = 0;
	int anonymize = 0;
	int offlinetype = MFF_PCAP;
	int tofiletype = MFF_PCAP;
	int sleep=0;
	int print_ifindex = 0;
	int if_capt = -1;
	char *key=NULL;
	mapi_flow_info_t info;
	time_t start,runtime;
	
	mapi_results_t *run;
	
	struct mapipkt *pkt = NULL;

	progname = strdup(argv[0]);

	/* reading line args */
	
	while((opt = getopt(argc, argv, "Xa:vhc:r:w:s:d:e:x:l:i:j")) != EOF)
	{
			switch(opt)
			{
				case 'X':
					fullpacket = 1;
					break;
				case 'a':
				        key = strdup(optarg);
					if(strlen(key)<32) {
					  printf("Key must be 256bit long");
					  exit(-1);
					}
					anonymize = 1;
					break;
				case 'h':
					usage();
					break;			
				case 'v':
					verbose = 1;
					break;
				case 'c':
					to_count = 0;
					count = atoi(optarg);
					break;
			case 'l':
			  sleep=atoi(optarg);
			  break;
				case 'r':
					offline = 1;
					readfile = strdup(optarg);
					break;
				case 'e':
					offline = 1;
					offlinetype = MFF_DAG_ERF;
					readfile = strdup(optarg);
					break;
				case 'w':
					to_file = 1;
					writefile = strdup(optarg);
					break;	
				case 'x':
					to_file = 1;
					tofiletype = MFF_RAW;
					writefile = strdup(optarg);
					break;	
				case 's':
					str_search = 1;
					searchstring = strdup(optarg);
					break;			      
				case 'd':
					DEV = strdup(optarg);
					break;
  			        case 'i':
					if_capt = atoi(optarg);
					break;
			        case 'j':
					print_ifindex = 1;
					break;
				default:
					panic("missing argument to -%c\n", optopt);
			}
	}

	/* grab BPF filter expression */

	argc -= optind;
	argv += optind;

	cp = filterbuf;

	for( ; argc; argc--, argv++)
	{
		cp += snprintf(cp, &filterbuf[sizeof(filterbuf)]-cp, "%s ", argv[0]);
	}

	if(cp != filterbuf)
		*cp = '\0';

	if(offline)
	{
		DEV= mapi_create_offline_device(readfile, offlinetype);
	}

	fd = mapi_create_flow(DEV);

	if(fd < 0)
	{
		//mapi_read_error(&errno,errbuf);
		panic("Error: %d - %s\n", errno, errbuf);
		
		return -1;
	}

	if(sleep>0) {
	  sprintf(str,"+%ds",sleep);
	  mapi_apply_function(fd,"STARTSTOP","+0s",str);
	}
	
	if(if_capt >= 0) 
	{
		fidi = mapi_apply_function(fd, "INTERFACE", if_capt);
		
		if(fidi < 0)
		{
		//	mapi_read_error(&errno,errbuf);
			panic("Error: %d - %s\n", errno, errbuf);
		
			return -1;
		}
	}

	if(*filterbuf)
	{
		fidf = mapi_apply_function(fd, "BPF_FILTER", filterbuf);
		
		if(fidf < 0)
		{
		//	mapi_read_error(&errno,errbuf);
			panic("Error: %d - %s\n", errno, errbuf);
		
			return -1;
		}

	}
	
	if(str_search)
	{
		fids = mapi_apply_function(fd, "STR_SEARCH", searchstring, 0, 1500);

		if(fids < 0)
		{
			mapi_read_error(&errno,errbuf);
			panic("Error: %d - %s\n", errno, errbuf);
		
			return -1;
		}

	}

	if(anonymize == 1)
	    mapi_apply_function(fd,"ANONYMIZEIP",key);
	
	if(to_file == 1)
	{
	
		if(!writefile)
		{
			printf("Must specify a file to write to\n");

			return -1;
		}
		
		if((fid = mapi_apply_function(fd, "TO_FILE", tofiletype, writefile, count)) == -1)
		{
			mapi_read_error(&errno,errbuf);
			panic("Error: %d - %s\n", errno, errbuf);
			
			return -1;
		}
	}
	else
	{
		
		bufid = mapi_apply_function(fd, "TO_BUFFER", 0);

		if(bufid < 0)
		{
			mapi_read_error(&errno,errbuf);
			panic("Error: %d - %s\n", errno, errbuf);
		
			return -1;
		}
	}

	if(mapi_connect(fd) < 0)
	{
		mapi_read_error(&errno, errbuf);
		panic("Error: %d - %s\n", errno, errbuf);

		return -1;
	}

	if(offline)
		mapi_start_offline_device(DEV);

	
	info.status=FLOW_INIT;

	time(&start);

	while(!offline || (offline && info.status!=FLOW_FINISHED))
	{
		if(to_file == 1)
		{
			run = mapi_read_results(fd, fid);
    	
			if(*((int*)run->res)==0)
			  {
			    printf("File written.\n");
			    mapi_close_flow(fd);
			    exit(0);
			  }
			else
			  {
			    usleep(10);
			    if(sleep>0) {
			      time(&runtime);
			      if(runtime-start>sleep) {
				mapi_close_flow(fd);
				exit(0);
			      }
			    }
			  }

		}
		else
		{
			
			pkt=mapi_get_next_pkt(fd, bufid);
	
			if(pkt == NULL)
			{
				mapi_read_error(&errno, errbuf);
				printf("Error: %d - %s\n", errno, errbuf);

				continue;
			}

			print_mapi_pkt(pkt , fullpacket, print_ifindex);

			printf("------------------------------------------------------------------------------------------\n");
	
			cnt++;

			if(cnt == count)
				break;
		}
		if(offline)
		  mapi_get_flow_info(fd,&info);
	}

	mapi_close_flow(fd);

	return 0;
}

static char usgtxt[] = "\
%s: tcpdump version using MAPI.\n\
Usage: %s [-Xvh] \n\
       %s [-Xvha] [-c count] [-r file] [-w file] [-s string] [-d device] [filter expression]\n\
  -a   <256bit key> anonymize IP addresses\n\
  -h   this page\n\
  -X   print payload\n\
  -v   increase verbosity\n\
  -c   <num> work till count packets\n\
  -r   <file> read packets from pcap file\n\
  -e   <file> read packets from DAG ERF file\n\
  -w   <file> write packets to file using pcap format\n\
  -x   <file> write packets to file using raw format\n\
  -s   <string> string to search in payload\n\
  -l   <seconds> runtime in seconds\n\
  -d   <device> device (default \"/dev/dag0\")\n\
  -i   <ifindex> ifindex\n\
  -j   print ifindex\n\
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

