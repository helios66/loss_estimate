#ifndef NPROBE_PRIV_H
#define NPROBE_PRIV_H

typedef struct {
  void *data;
  void *next;
} np_list_t;

extern np_ctxt_t *npInitContext(void);
extern void npInitGlobals(void);
extern int initNetFlow(np_ctxt_t *npctxt, char* addr, int port);
extern void* dequeueBucketToExport(void* ctxt);
extern void* hashWalker(void* ctxt);
extern void shutdownNprobe(void);
extern void shutdownInstance(np_ctxt_t *npctxt);
extern void npInitCounters(np_ctxt_t *npctxt);
extern void processPacket(u_char *_deviceId,
			  const struct pcap_pkthdr *h,
			  const u_char *p);
extern void restoreInterface(np_ctxt_t *npctxt, char ebuf[]);
extern void dummyProcessPacket(u_char *_deviceId,
			       const struct pcap_pkthdr *h,
			       const u_char *p);

/* *********** Globals ******************* */

extern np_list_t *np_contexts;
extern int nInstances;
#ifdef linux
extern u_char useMmap;
#endif

/* Threads */
extern pthread_mutex_t exportMutex, purgedBucketsMutex, hashMutex[MAX_HASH_MUTEXES];


#endif  /* NPROBE_PRIV_H */
