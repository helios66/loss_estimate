#ifndef NPCTXT_H
#define NPCTXT_H

#include <pcap.h>
#include "services.h"
#include "drivers/mapidlib.h"


#ifndef WIN32
#include <pthread.h>

typedef struct conditionalVariable {
  pthread_mutex_t mutex;
  pthread_cond_t  condvar;
  int predicate;
} ConditionalVariable;

#else
#error "Add thread support!"

typedef struct conditionalVariable {
  HANDLE condVar;
  CRITICAL_SECTION criticalSection;
} ConditionalVariable;

#endif

#define FLOW_VERSION_5		 5
#define V5FLOWS_PER_PAK		30
#define DEBUG_JK

struct flow_ver5_hdr {
  u_int16_t version;         /* Current version=5*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int8_t  engine_type;     /* Type of flow switching engine (RP,VIP,etc.)*/
  u_int8_t  engine_id;       /* Slot number of the flow switching engine */
  u_int16_t sampleRate;      /* Packet capture sample rate */
};

struct flow_ver5_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration (milliseconds between 1st
			   & last packet in this flow)*/
  u_int32_t dOctets;    /* Octets sent in Duration (milliseconds between 1st
			   & last packet in  this flow)*/
  u_int32_t First;      /* SysUptime at start of flow */
  u_int32_t Last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t pad1;        /* pad to word boundary */
  u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
  u_int8_t prot;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t tos;         /* IP Type-of-Service */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t dst_mask;    /* destination route's mask bits */
  u_int8_t src_mask;    /* source route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
};

typedef struct single_flow_ver5_rec {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[V5FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow5Record;

/* ************************************ */

/* NetFlow v9/IPFIX */

typedef struct flow_ver9_hdr {
  u_int16_t version;         /* Current version=9*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t sourceId;        /* Source id */
} V9FlowHeader; 

typedef struct flow_ipfix_hdr {
  u_int16_t version;         /* Current version=0x0a*/
  u_int16_t length;          /* The length of the IPFIX packet, w/hdr+records. */
  u_int32_t exportTime;      /* Export time, seconds since jan1 1970 0:0 UTC */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t sourceId;        /* Source id */
} IPFIXFlowHeader; 



typedef struct flow_ver9_template_field {
  u_int16_t fieldType;
  u_int16_t fieldLen;
} V9TemplateField;

typedef struct flow_ver9_template {
  u_int16_t templateFlowset; /* = 0 for nfv9, 2 for ipfix */
  u_int16_t flowsetLen;
  u_int16_t templateId;
  u_int16_t fieldCount;
} V9Template;

typedef struct flow_ver9_flow_set {
  u_int16_t templateId;
  u_int16_t flowsetLen;
} V9FlowSet;

typedef struct flow_ver9_templateids {
  u_int16_t templateId;
  u_int16_t templateLen;
  char      *templateDescr;
} V9TemplateId;

#define NFLOW_VERSION 24

/* **************************************

   +------------------------------------+
   |           nFlow Header             |
   +------------------------------------+
   |           nFlow Flow 1             |
   +------------------------------------
   |           nFlow Flow 2             |
   +------------------------------------+
   ......................................
   +------------------------------------
   |           nFlow Flow n             |
   +------------------------------------+

   NOTE: nFlow records are sent in gzip format
   
   ************************************** */

#define NFLOW_SUM_LEN             16
#define NFLOW_SIZE_THRESHOLD    8192
#define MAX_PAYLOAD_LEN         1400
/* FIXME: Can't have more than 1 until FIXME at bottom of addPktToHash is taken care 
   of. Besides, we did not measure worse performace with 1.
#define MAX_HASH_MUTEXES          32
*/
#define MAX_HASH_MUTEXES           1

/* nFlow Header */
typedef struct nflow_ver1_hdr_ext {
  /* NetFlow v5 header-like */
  u_int16_t version;         /* Current version=1 (nFlow v1) */
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  /* nFlow Extensions */
  u_int32_t sourceId;        /* Source id */
  u_int16_t sampleRate;      /* Sampling rate */
  u_int16_t pad;             /* Not Used */
  u_char    md5Sum[NFLOW_SUM_LEN];      /* MD5 summary */
} NflowV1Header;

typedef struct nflow_flow_item {
  u_int16_t fieldType;
  u_int16_t fieldLen;
  char      *flowData;
} NflowV1FlowItem;

/* nFlow Flow */
typedef struct nflow_flow {
  u_int16_t flowsetLen;
} NflowV1FlowRecord;

#ifdef WIN32
typedef float Counter;
#else
typedef unsigned long long Counter;
#endif

typedef struct collectorAddress {
  u_char isV6; /* 0=IPv4, 1=IPv6 */
  union {
    struct sockaddr_in v4Address;
#ifndef IPV4_ONLY
    struct sockaddr_in6 v6Address;
#endif
  } u;
} CollectorAddress;

/* ************************************ */
#define MAX_NUM_COLLECTORS          8

#define PAYLOAD_EXCERPT_MAX       16

typedef struct ipV4Fragment {
  u_int32_t src, dst;
  u_short fragmentId, numPkts, len, sport, dport;
  time_t firstSeen;
  struct ipV4Fragment *next;
} IpV4Fragment;

#define TEMPLATE_LIST_LEN   45

typedef struct np_ctxt_t {
  void *mapi_ctxt; /* MAPI shared memory context */
  pthread_t dequeueThread;
  pthread_t walkHashThread;
  ConditionalVariable  exportQueueCondvar;
  int instanceNo;		/* Used when logging/tracing */
  char shutdownInProgress;
  HashBucket **hash;
  u_int32_t hashSize;
  u_int walkIndex;
  u_char useNetFlow;
  u_char netFlowVersion;
  u_char templateSent;
  u_short collectorId;
  CollectorAddress netFlowDest[MAX_NUM_COLLECTORS]; /* Collectors addresses */
  u_char useIpV6;
  u_int8_t numCollectors; 
  u_char ignoreTcpUdpPorts;
  u_char ignoreIpAddresses;
  u_char ignoreTos;
  u_char tcpPayloadExport;
  u_char udpPayloadExport;
  u_char icmpPayloadExport;
  u_char otherPayloadExport;
  u_short maxPayloadLen;
  u_int   minFlowPkts;		/* Minimum flow size - in packets - to include in export */
  u_char computeFingerprint;
  u_char compressFlows;
  u_short flowExportDelay;  /* microsec */
  u_char *textFormat;
  u_int32_t bufferLen;
  int numFlows;
  int netFlowOutSocket;
  FILE *fileexportHandle;
  char *fileexportName;
  u_int16_t traceMode;
  u_int16_t traceToFile;
  u_int16_t minNumFlowsPerPacket; /* FlowSets are sent when this number is hit */
  u_int16_t maxNumFlowsPerPacket; /* Max size of a flowset. Not enforced! */

  /* Last time a FlowSet was physically sent. See also flowExportDelay. */
  unsigned long long lastExportTime;
  unsigned long long lastTmpltExportTime;
  u_short idleTimeout;
  u_short lifetimeTimeout;
  u_short sendTimeout;
  u_short tmpltTimeout;
  u_short cacheTimeout;         /* How long service type etc. cached after flow export */
  u_int sampleRate;
  u_char nFlowKey[16];
  char *netFilter;
  u_char usePcap;
  pcap_t *pcapPtr;
  char *tmpDev;			/* Device name, not used with mapi */
  unsigned char *npBuffer;
  FILE *flowFd;			/* Not used with mapi */
  u_int32_t exportBucketsLen;
  HashBucket *exportQueue;
  HashBucket *exportQueueEnd;
  NetFlow5Record v5Flow;
  IPFIXFlowHeader ipfixHeader;
  V9FlowHeader v9Header;
  NflowV1Header nFlowHeader;
  V9TemplateId *v9TemplateList[TEMPLATE_LIST_LEN];
  Counter totalPkts;
  Counter totalBytes;
  Counter totalTCPPkts;
  Counter totalTCPBytes;
  Counter totalUDPPkts;
  Counter totalUDPBytes;
  Counter totalICMPPkts;
  Counter totalICMPBytes;
  time_t  lastSample;
  Counter currentPkts;
  Counter currentBytes;
  Counter currentTCPPkts;
  Counter currentTCPBytes;
  Counter currentUDPPkts;
  Counter currentUDPBytes;
  Counter currentICMPPkts;
  Counter currentICMPBytes;
  Counter sumBucketSearch;
  unsigned long initialPktsDropped;
  u_int numExports;
  u_int totFlows;
  HashBucket *purgedBuckets;
  u_int32_t purgedBucketsLen;
  u_int bucketsAllocated;
  IpV4Fragment *fragmentsList;
  u_int32_t fragmentListLen;
  u_int maxBucketSearch;
  u_int lastMaxBucketSearch;
  u_int32_t flowSequence;
  u_int64_t numObservedFlows;
  unsigned long long initialSniffTime;
  u_short scanCycle /* sec */;

  /* Enterprise ID used for IPFIX custom fields
   * See http://www.iana.org/assignments/enterprise-numbers */
  u_int32_t enterpriseId;

  u_int8_t  histPktSizeEnabled;
  u_int8_t  histPktDistEnabled;
  u_int16_t histPktSizeBucket[PKTSZ_HISTOGRAM_SLOTS];
  u_int16_t histPktDistBucket[PKTDIST_HISTOGRAM_SLOTS];
  u_int8_t  bitrateCalcEnabled; /* Bitset, see BITRATE_* flags for options */

  uint8_t  pktDistLengthStddevs;
  
  /* Exporter's addresses */
  u_int32_t exporterIpv4Address; /* in_addr */
  struct in6_addr exporterIpv6Address;

  /* Number of flows, packets, and octets dropped by emitter */
  u_int64_t notsent_flows;
  u_int64_t notsent_pkts;
  u_int64_t notsent_octets;

  /* Number (and size) of IPFIX messages that have been exported */
  u_int64_t exportedOctetTotalCount;
  u_int64_t exportedMessageTotalCount;
  u_int64_t exportedFlowsTotalCount;
  u_int64_t exportedFlowsSinceLastPkt; /* ... since last export pkt was started */

  /* Number of packets that were malformed or uninteresting, and therefore ignored */
  u_int64_t ignoredPacketTotalCount;
  u_int64_t ignoredOctetTotalCount;

  /* Number of seconds that one flow may be queued for export. Old flows aren't */
  /* exported in order to avoid congestion. This is max num of seconds to keep. */
  u_int32_t maxExportQueueLatency;

  /* V9/IPFix template ID for the data that is exported. Should be unique */
  /* within a bound time frame when using different templates. Is >=256 for IPFix. */
  u_int16_t templateID;

  /*
   * Observation Domain ID (Netflow v9: Source ID). Identifies the exporters
   * domain uniquely. Template ID and Observation Domain IDs  must be unique
   * within the scope of all observation points.
   */
  u_int32_t observationDomainID;

  /*
   * If service classification is turned on.
   */
  u_int8_t serviceClassification;
  
  /*
   * If RTCP classification is turned on
   */
  u_int8_t rtcp_enabled;

  struct mapid_dc *service_dc;
  struct mapid_torrent *service_torrent;
  struct mapid_sip *service_sip;

  u_int16_t ingress_interface;
  u_int16_t egress_interface;

  struct mapid_hw_info *hwinfo;
  u_int32_t statInterval;
  u_int32_t statSkipCnt;
  u_int16_t logfileOpened;
  FILE      *loghandle;
#ifdef DEBUG_JK
  u_int32_t endCntIdle;
  u_int32_t endCntActive;
  u_int32_t endCntEof;
  u_int32_t endCntForced;
  u_int32_t endCntCacheExpired;
  u_int32_t cacheCnt;
  u_int32_t uncacheCnt;
  u_int32_t torrentCnt;
  u_int32_t rtpCnt;
#endif

} np_ctxt_t;

#endif
