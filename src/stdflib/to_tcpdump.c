#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "mapidflib.h"
#include "mapi_errors.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "debug.h"

struct to_tcpdump_data
{
  unsigned long long maxpkts;
  unsigned long long pkts;
  int file;
};

//For 64-bit compatibility
struct pcap_timeval {
  int tv_sec;           /* seconds */
  int tv_usec;          /* microseconds */
};

struct pcap_sf_pkthdr {
  struct pcap_timeval ts;     /* time stamp */
  int caplen;         /* length of portion present */
  int len;            /* length this packet (off wire) */
};


static int to_tcpdump_instance(mapidflib_function_instance_t *instance,
			       MAPI_UNUSED int fd,
			       MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  mapiFunctArg* a=instance->args;
  int type = getargint(&a), file;
  if(type==MFF_RAW || type==MFF_PCAP)
    return 0;
  else
    return(MFUNCT_COULD_NOT_APPLY_FUNCT);

  file = getargint(&a);
  if(file < 0)
	  return(MFUNCT_COULD_NOT_APPLY_FUNCT);
  else
  {
	  struct stat buf;
	  if(fstat(file, &buf) == -1)
	  {
		  DEBUG_CMD(Debug_Message("to_tcpdump_instance(): Cannot fstat() file descriptor %d", file));
		  return(MFUNCT_INVALID_ARGUMENT_2);
	  }
  }
}

static int to_tcpdump_init(mapidflib_function_instance_t *instance,
			   MAPI_UNUSED int fd)
{
  int *res;
  struct to_tcpdump_data* i=malloc(sizeof(struct to_tcpdump_data)); 
  struct pcap_file_header head;

  mapiFunctArg* fargs=instance->args;
  getargint(&fargs);

  //Open file for writing
  i->file=getargint(&fargs);

  if(i==NULL) {
    return MFUNCT_COULD_NOT_INIT_FUNCT;
  }

  i->maxpkts=getargulonglong(&fargs);
  i->pkts=0;
  instance->internal_data=i;
  res=instance->result.data;
  *res=11;

  //Write PCAP header
  head.magic=2712847316U;
  head.version_major=2;
  head.version_minor=4;
  head.thiszone=0;
  head.sigfigs=0;
  head.snaplen=instance->hwinfo->cap_length;
  head.linktype=instance->hwinfo->link_type;

  write(i->file,&head,sizeof(struct pcap_file_header));
  return 0;
}


static int to_tcpdump_process(mapidflib_function_instance_t *instance,MAPI_UNUSED unsigned char* dev_pkt,unsigned char* link_pkt,mapid_pkthdr_t* pkthdr)
{
  struct pcap_sf_pkthdr phdr;
  struct to_tcpdump_data *i=instance->internal_data;
  int *res=instance->result.data;
  unsigned long long ts;

  if(i->pkts >= i->maxpkts && i->maxpkts!=0) {      
    *res=0;
    return 1;
  }

  phdr.caplen=pkthdr->caplen;
  phdr.len=pkthdr->wlen;

  ts=pkthdr->ts;
  phdr.ts.tv_sec = (long)(ts >> 32);
  ts = ((ts & 0xffffffffULL) * 1000 * 1000);
  ts += (ts & 0x80000000ULL) << 1;        /* rounding */
  phdr.ts.tv_usec = (long)(ts >> 32);
  if(phdr.ts.tv_usec >= 1000000) {
  	phdr.ts.tv_usec -= 1000000;
    phdr.ts.tv_sec += 1;
  }

  write(i->file,&phdr,sizeof(struct pcap_sf_pkthdr));
  write(i->file,link_pkt,pkthdr->caplen);
  i->pkts++;
  return 1;
}


static int to_tcpdump_cleanup(mapidflib_function_instance_t *instance) {
  struct to_tcpdump_data *i=instance->internal_data;
  if (i!=NULL && i->file)
    close(i->file);
  
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "TO_FILE",
  "To_Tcpdump saves packetflow into tcpdump file.\nParameters:\n\tfilename : char*\n\tmaxpos: unsigned long long",
  "iwl",
  MAPI_DEVICE_ALL,
  MAPIRES_SHM,
  sizeof(int), //shm size
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  to_tcpdump_instance,
  to_tcpdump_init,
  to_tcpdump_process,
  NULL,
  NULL,
  to_tcpdump_cleanup,
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* to_tcpdump_get_funct_info();
mapidflib_function_def_t* to_tcpdump_get_funct_info() {
  return &finfo;
};
