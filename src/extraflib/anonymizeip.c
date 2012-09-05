#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "debug.h"
#include "panonymizer.h"
#include "protocols.h"
#include "pcap-bpf.h"

typedef struct anonip_inst {
  panon_t anon_instance;

} anonip_inst_t;

static int anonymizeip_process(mapidflib_function_instance_t *instance,
			 MAPI_UNUSED unsigned char* dev_pkt,
			 unsigned char* link_pkt,
			 MAPI_UNUSED mapid_pkthdr_t* pkt_head)
{
  struct ip *ip;
  struct ip6_hdr *ip6;
  uint64_t orig6[2], anon6[2];
  anonip_inst_t *i = instance->internal_data;
  unsigned int len = instance->hwinfo->cap_length;

  switch(instance->hwinfo->link_type) {
  case DLT_EN10MB: // Ethernet
    ip = (struct ip *)(link_pkt + sizeof(ether_header));
    len -= sizeof(ether_header);
    break;
  case DLT_CHDLC: // PoS
    ip = (struct ip *)(link_pkt + 4);
    len -= 4;
    break;
  default:
    DEBUG_CMD(Debug_Message("Link layer not supported"));
    exit(-1);
  }

  if (len < sizeof(struct ip))
    return 0;

  switch(ip->ip_v) {
  case 4:
      ip->ip_src.s_addr = htonl(anonymize(&i->anon_instance, ntohl(ip->ip_src.s_addr)));
      ip->ip_dst.s_addr = htonl(anonymize(&i->anon_instance, ntohl(ip->ip_dst.s_addr)));
      break;
  case 6:
      if (len < sizeof(struct ip6_hdr))
	return 0;
      ip6 = (struct ip6_hdr *)ip;
      //See panonymizer.h for IPv6 support
      memcpy(orig6, &ip6->ip6_src, 16);
      anonymize_v6(&i->anon_instance, orig6, anon6);
      memcpy(&ip6->ip6_src, anon6, 16);
      memcpy(orig6, &ip6->ip6_dst, 16);
      anonymize_v6(&i->anon_instance, orig6, anon6);
      memcpy(&ip6->ip6_dst, anon6, 16);
      break;
  default:
    return 0;
  }
  return 1;
}

static int anonymizeip_init(mapidflib_function_instance_t *instance,
		      MAPI_UNUSED int flow_descr)
{
  anonip_inst_t *i=malloc(sizeof(anonip_inst_t));
  mapiFunctArg* fargs=instance->args;
  char *str;

  instance->internal_data=i;

  str=getargstr(&fargs);

  PAnonymizer_Init(&i->anon_instance,str);
  
  return 0;
}

static mapidflib_function_def_t finfo={
  "",
  "ANONYMIZEIP",
  "Anonymizes src/dst IP addresses. Takes a 256-bit string key as argument",
  "s",
  MAPI_DEVICE_ALL,
  MAPIRES_SHM,
  sizeof(unsigned long long), //shm size
  1, //TODO: This should be changed to 1
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  NULL, //instance
  anonymizeip_init, //init
  anonymizeip_process,
  NULL, //get_result
  NULL, //reset
  NULL, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* anonymizeip_get_funct_info();
mapidflib_function_def_t* anonymizeip_get_funct_info() {
  return &finfo;
};



