#ifndef NPKTPROC_H
#define NPKTPROC_H

#define HLDC_HDRLEN 4

extern void nprobeProcessPacket(void *ctxt, 
				mapid_pkthdr_t *pkt_head, const void *pkt);

#endif
