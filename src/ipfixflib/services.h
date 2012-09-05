#ifndef IPFIX_SERVICES_H
#define IPFIX_SERVICES_H

#define DC_STRING_NUM 15
#define TOR_STRINGS_NO 16
#define SIP_STRINGS_NO 4

#if 1
#define __WITH_AHO__
#include "acsmx2.h"
#endif

#include "mpegts.h"

struct mapid_dc {
	int *shift[DC_STRING_NUM];
	int *skip[DC_STRING_NUM];
};
struct mapid_torrent {
#ifndef __WITH_AHO__
	int *shift[TOR_STRINGS_NO];
	int *skip[TOR_STRINGS_NO];
#else
	ACSM_STRUCT2 *acsm;
        int match_index;
        char *found;
#endif
	unsigned int search_len[TOR_STRINGS_NO]; 
};

struct mapid_sip {
#ifndef __WITH_AHO__
	int *shift[SIP_STRINGS_NO];
	int *skip[SIP_STRINGS_NO];
#else
	ACSM_STRUCT2 *acsm;
        int match_index;
        char *found;
#endif
	unsigned int search_len[SIP_STRINGS_NO]; 
};

struct np_ctxt_t;

extern int serviceClassification(struct np_ctxt_t *npctxt, u_short proto, u_short sport, 
				 u_short dport, u_char *payload, int payloadLen);

extern void serviceClassificationFree(struct np_ctxt_t *npctxt);
#endif
