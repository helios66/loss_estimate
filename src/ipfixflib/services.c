#include <mapi.h>

#include "debug.h"
#include "nprobe.h"
#include "nprobe-priv.h"
#include "ifp-priv.h"

#include "mstring.h"
#include "services.h"
#include "mapi_errors.h"

#include "mpegts.h"
/*
 * DC and Torrent functionality by Trackflib (../trackflib)
 *
 */



static char *dc_strings[DC_STRING_NUM]= {
	"$MyNick",
	"$Lock EXTENDEDPROTOCOL",
	"$Sending",
	"$Direction Download ",
	"$Direction Upload ",
	"$Supports",
	"$GetNickList|",
	"$ValidateNick",
	"$ConnectToMe",
	"$HubName",
	"$Hello",
	"$MyINFO $ALL",
	"$GetINFO",
	"$Search Hub:",
	"$OpList"
};

static char *torrent_strings[TOR_STRINGS_NO]= {
	"BitTorrent protocol",
	"GET /scrape?info_hash=",
	"GET /announce?info_hash=",
	"d1:rd2:id20:",
	"d1:ad2:id20:",
	"User-Agent: Azureus",
	"/scrape?info_hash=",
	"BT_PIECE",
	"BT_REQUEST",
	"BT_CHOKE",
	"BT_UNCHOKE",
	"BT_HAVE",
	"BT_UNINTERESTED",
	"BT_INTERESTER",
	"BT_BITFIELD",
	"BT_CANCEL"
};

static int torrent_lens[TOR_STRINGS_NO]={20, 100, 100, 20, 20, 100, 100, 50, 50, 50, 50, 50, 50, 50, 50 , 50};

static char *sip_strings[SIP_STRINGS_NO]= {
	"INVITE",
	"SIP/2.0",
	"Call-ID:",
	"CSeq:"
};

static int sip_lens[SIP_STRINGS_NO]={20, 100, 500, 500};

static int
isDc(np_ctxt_t *npctxt, unsigned char *pkt, unsigned int len, MAPI_UNUSED u_short sport,MAPI_UNUSED u_short dport)
{
	int i;
  
	if (!pkt || len == 0)
		return -1;

	if(npctxt->service_dc==NULL) {
		npctxt->service_dc = (struct mapid_dc *)malloc(sizeof(struct mapid_dc));

		for(i=0;i<DC_STRING_NUM;i++) {
			npctxt->service_dc->shift[i] = make_shift(dc_strings[i], strlen(dc_strings[i]));
			npctxt->service_dc->skip[i] = make_skip(dc_strings[i], strlen(dc_strings[i]));
		}    
	}
  
  
	for(i=0;i<DC_STRING_NUM;i++) {
		if(len < strlen(dc_strings[i]))
			continue;
    
		if(len >= 100) {
			if(mSearch((char *)(pkt), 100, dc_strings[i], strlen(dc_strings[i]),
				   npctxt->service_dc->skip[i],
				   npctxt->service_dc->shift[i]))
			{
				return i;
			}
		}
		else {
			if(mSearch((char *)(pkt), len, dc_strings[i], strlen(dc_strings[i]),
				   npctxt->service_dc->skip[i],
				   npctxt->service_dc->shift[i]))
			{
				return i;
			}
		}
	}
	return -1;
  
}

static int
torrent_init(np_ctxt_t *npctxt) 
{
	int i;

	npctxt->service_torrent = (struct mapid_torrent *)malloc(sizeof(struct mapid_torrent));
	if (!npctxt->service_torrent) {
		return MAPID_MEM_ALLOCATION_ERROR;
	}
#ifndef __WITH_AHO__
	for(i=0;i<TOR_STRINGS_NO;i++) {
		npctxt->service_torrent->shift[i] = make_shift(torrent_strings[i],strlen(torrent_strings[i]));
		npctxt->service_torrent->skip[i] = make_skip(torrent_strings[i], strlen(torrent_strings[i]));
		npctxt->service_torrent->search_len[i] = torrent_lens[i];
	}  
#else
	npctxt->service_torrent->acsm = acsmNew2();
	if (!npctxt->service_torrent->acsm) {
		return MAPID_MEM_ALLOCATION_ERROR;
	}
	npctxt->service_torrent->match_index = -1;
	npctxt->service_torrent->found = NULL;
	 
	for (i = 1; i < TOR_STRINGS_NO; i++) {
		char *p = torrent_strings[i];
		 
	//	int acsmAddPattern2 (ACSM_STRUCT2 * p, unsigned char *pat, int n, int nocase,
	//		int offset, int depth, void * id, int iid) 
		DEBUG_CMD(Debug_Message("torrent_lens[%d] = %d", i, torrent_lens[i]));
		acsmAddPattern2(npctxt->service_torrent->acsm, (unsigned char *)p, strlen(p), 
				1, 0, torrent_lens[i],(void*)p, i);
	}
	 
	acsmCompile2(npctxt->service_torrent->acsm);
#endif

	return 0;
}

#ifdef __WITH_AHO__

static int
torrent_matchFound(void* id, int my_index, void *data) 
{
	struct mapid_torrent *mt = (struct mapid_torrent *) data ;
	DEBUG_CMD(Debug_Message("found %s index %d", (char *)id, my_index));
	mt->match_index = my_index;
	mt->found = (char *)id;

	return my_index;
}
#endif

static int
isTorrent(np_ctxt_t *npctxt, unsigned char *pkt, unsigned int len, u_short sport, u_short dport)
{
#ifndef __WITH_AHO__
		int i;
#endif

	if (!pkt || len == 0)
		return -1;

	if(sport == 411 || dport == 411) { // DC++?
		return -1;
	}
	if(sport == 4662 || dport == 4662) { // eDonkey?
		return -1;
	}

	if(npctxt->service_torrent==NULL) {
		(void) torrent_init(npctxt);
	}

	if((int)len>torrent_lens[0] && pkt[0] == 19 && (memcmp(&pkt[1], torrent_strings[0], 19) == 0))
		return 0;
  
#ifndef __WITH_AHO__
	for(i=1;i<TOR_STRINGS_NO;i++) {
		if(len < strlen(torrent_strings[i]))
			continue;
      
		if(npctxt->service_torrent->search_len[i] > len) {
			if(mSearch((char *)(pkt), len, torrent_strings[i], strlen(torrent_strings[i]),
				   npctxt->service_torrent->skip[i],
				   npctxt->service_torrent->shift[i])) {
				return i;
			}
		}
		else {
			if(mSearch((char *)(pkt), npctxt->service_torrent->search_len[i], 
				   torrent_strings[i], strlen(torrent_strings[i]),
				   npctxt->service_torrent->skip[i],
				   npctxt->service_torrent->shift[i])){
				return i;
			}
		}
	}
	return -1;
#else
	npctxt->service_torrent->match_index = -1;
	npctxt->service_torrent->found = NULL;
	acsmSearch2(npctxt->service_torrent->acsm, pkt, len, torrent_matchFound, (void *)npctxt->service_torrent);
  
	return npctxt->service_torrent->match_index;
#endif  
}


static int
sip_init(np_ctxt_t *npctxt) 
{
	int i;

	npctxt->service_sip = (struct mapid_sip *)malloc(sizeof(struct mapid_sip));
	if (!npctxt->service_sip) {
		return MAPID_MEM_ALLOCATION_ERROR;
	}
#ifndef __WITH_AHO__
	for(i=0;i<SIP_STRINGS_NO;i++) {
		npctxt->service_sip->shift[i] = make_shift(sip_strings[i],strlen(sip_strings[i]));
		npctxt->service_sip->skip[i] = make_skip(sip_strings[i], strlen(sip_strings[i]));
		npctxt->service_sip->search_len[i] = sip_lens[i];
	}  
#else
	npctxt->service_sip->acsm = acsmNew2();
	if (!npctxt->service_sip->acsm) {
		return MAPID_MEM_ALLOCATION_ERROR;
	}
	npctxt->service_sip->match_index = -1;
	npctxt->service_sip->found = NULL;
	 
	for (i = 1; i < SIP_STRINGS_NO; i++) {
		char *p = sip_strings[i];
		 
	//	int acsmAddPattern2 (ACSM_STRUCT2 * p, unsigned char *pat, int n, int nocase,
	//		int offset, int depth, void * id, int iid) 
		DEBUG_CMD(Debug_Message("sip_lens[%d] = %d", i, sip_lens[i]));
		acsmAddPattern2(npctxt->service_sip->acsm, (unsigned char *)p, strlen(p), 
				1, 0, sip_lens[i],(void*)p, i);
	}
	 
	acsmCompile2(npctxt->service_sip->acsm);
#endif

	return 0;
}

#ifdef __WITH_AHO__

static int
sip_matchFound(void* id, int my_index, void *data) 
{
	struct mapid_torrent *mt = (struct mapid_torrent *) data ;
	DEBUG_CMD(Debug_Message("found %s index %d", (char *)id, my_index));
	mt->match_index = my_index;
	mt->found = (char *)id;

	return my_index;
}
#endif


static int 
matchSip(np_ctxt_t *npctxt, unsigned char *pkt, unsigned int len)
{
#ifndef __WITH_AHO__
	for(i=1;i<SIP_STRINGS_NO;i++) {
		if(len < strlen(sip_strings[i]))
			continue;
      
		if(npctxt->service_sip->search_len[i] > len) {
			if(mSearch((char *)(pkt), len, sip_strings[i], strlen(sip_strings[i]),
				   npctxt->service_sip->skip[i],
				   npctxt->service_sip->shift[i])) {
				return i;
			}
		}
		else {
			if(mSearch((char *)(pkt), npctxt->service_sip->search_len[i], 
				   sip_strings[i], strlen(sip_strings[i]),
				   npctxt->service_sip->skip[i],
				   npctxt->service_sip->shift[i])){
				return i;
			}
		}
	}
	return -1;
#else
	npctxt->service_sip->match_index = -1;
	npctxt->service_sip->found = NULL;
	acsmSearch2(npctxt->service_sip->acsm, pkt, len, sip_matchFound, (void *)npctxt->service_sip);
  
	return npctxt->service_sip->match_index;
#endif
}




static int
isSip(np_ctxt_t *npctxt, unsigned char *pkt, unsigned int len, u_short sport, u_short dport)
{
	int res;

	if (!pkt || len == 0)
		return -1;

	if (dport != 5060 && sport != 5060)
		return -1;

	if(npctxt->service_sip==NULL)
		(void) sip_init(npctxt);

	res = matchSip((np_ctxt_t *)npctxt, pkt, len);
	if (res >=0)
		return res;
	else
		return -1;
}

int serviceClassification(struct np_ctxt_t *npctxt, MAPI_UNUSED u_short proto, u_short sport, 
			  u_short dport, u_char *payload, int payloadLen) {
	/*
	 *  if(isDc((np_ctxt_t *)npctxt, payload, payloadLen, sport, dport)>=0)
	 *   return 1;
	 *  else 
	 */

        int res = 0;

	if(isTorrent((np_ctxt_t *)npctxt, payload, payloadLen, sport, dport)>=0)
		res = SERVICE_TORRENT;
	else if (isSip((np_ctxt_t *)npctxt, payload, payloadLen, sport, dport)>=0)
		res = SERVICE_SIP;
	else if (is_mpegts((char *)payload, payloadLen)>=0)
		res = SERVICE_MPEGTS;
#ifdef DEBUG_JK
	if (res != 0 && res != SERVICE_TORRENT && res != SERVICE_MPEGTS) {
	  printf("serviceClassification returns %d\n", res);
	}
#endif
	return res;
}

void serviceClassificationFree(struct np_ctxt_t *npctxt)
{
  if (npctxt->service_torrent) {
    if (npctxt->service_torrent->acsm) {
      acsmFree2(npctxt->service_torrent->acsm);
      free(npctxt->service_torrent->acsm);
    }
    free(npctxt->service_torrent);
  }
}
