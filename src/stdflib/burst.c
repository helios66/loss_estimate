// Module burst.c

// Implementation dependencies ------------------------------------------------

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "mapi_errors.h"

//#include <papi.h>
//#define NUM_EVENTS 2

#include "burst.h"

// End Implementation dependencies --------------------------------------------

// Debugging {{{
// informations about received packets
//#define __BURST_DEBUG
// informations about manipulation with received packets
//#define __BURST_VERBOSE
// print lag/lead for each packets (if you need some stats...)
//#define __BURST_DEBUG_LAG_LEAD
// print maximal/minimal lag/lead (if you need some stats...)
//#define __BURST_DEBUG_LAG_LEAD_MAX
// print warning if timestamping is not reliable (typically at NIC card)
//#define __BURST_DEBUG_WARNINGS
// }}}

// fixed point ntp timestamp aritmetics

#define s_char char
#define u_int32	unsigned long
#define int32	long

typedef struct {
	union {
		u_int32 Xl_ui;
		int32 Xl_i;
	} Ul_i;
	union {
		u_int32 Xl_uf;
		int32 Xl_f;
	} Ul_f;
} l_fp;

#define l_ui	Ul_i.Xl_ui /* unsigned integral part */
#define	l_i	Ul_i.Xl_i    /* signed integral part */
#define	l_uf	Ul_f.Xl_uf /* unsigned fractional part */
#define	l_f	Ul_f.Xl_f    /* signed fractional part */

typedef int32 s_fp;
typedef u_int32 u_fp;

/*
 * Primitive operations on long fixed point values.  If these are
 * reminiscent of assembler op codes it's only because some may
 * be replaced by inline assembler for particular machines someday.
 * These are the (kind of inefficient) run-anywhere versions.
 */
#define M_NEG(v_i, v_f)   /* v = -v */ \
  do { \
    if ((v_f) == 0) \
      (v_i) = -((s_fp)(v_i)); \
    else { \
      (v_f) = -((s_fp)(v_f)); \
      (v_i) = ~(v_i); \
    } \
  } while(0)
#define M_ADD(r_i, r_f, a_i, a_f) 	/* r += a */ \
	do { \
		register u_int32 lo_tmp; \
		register u_int32 hi_tmp; \
		\
		lo_tmp = ((r_f) & 0xffff) + ((a_f) & 0xffff); \
		hi_tmp = (((r_f) >> 16) & 0xffff) + (((a_f) >> 16) & 0xffff); \
		if (lo_tmp & 0x10000) \
			hi_tmp++; \
		(r_f) = ((hi_tmp & 0xffff) << 16) | (lo_tmp & 0xffff); \
		\
		(r_i) += (a_i); \
		if (hi_tmp & 0x10000) \
			(r_i)++; \
	} while (0)
#define M_SUB(r_i, r_f, a_i, a_f)	/* r -= a */ \
	do { \
		register u_int32 lo_tmp; \
		register u_int32 hi_tmp; \
		\
		if ((a_f) == 0) { \
			(r_i) -= (a_i); \
		} else { \
			lo_tmp = ((r_f) & 0xffff) + ((-((s_fp)(a_f))) & 0xffff); \
			hi_tmp = (((r_f) >> 16) & 0xffff) \
			    + (((-((s_fp)(a_f))) >> 16) & 0xffff); \
			if (lo_tmp & 0x10000) \
				hi_tmp++; \
			(r_f) = ((hi_tmp & 0xffff) << 16) | (lo_tmp & 0xffff); \
			\
			(r_i) += ~(a_i); \
			if (hi_tmp & 0x10000) \
				(r_i)++; \
		} \
	} while (0)

/*
 * Operations on the long fp format
 */
#define L_ADD(r, a) M_ADD(r.l_ui, r.l_uf, a.l_ui, a.l_uf)
#define	L_SUB(r, a)	M_SUB(r.l_ui, r.l_uf, a.l_ui, a.l_uf)

/*
 * l_fp/double conversions
 */
#define FRAC		4294967296. 		/* 2^32 as a double */
#define M_DTOLFP(d, r_i, r_uf) 			/* double to l_fp */ \
	do { \
		register double d_tmp; \
		\
		d_tmp = (d); \
		if (d_tmp < 0) { \
			d_tmp = -d_tmp; \
			(r_i) = (int32)(d_tmp); \
			(r_uf) = (u_int32)(((d_tmp) - (double)(r_i)) * FRAC); \
			M_NEG((r_i), (r_uf)); \
		} else { \
			(r_i) = (int32)(d_tmp); \
			(r_uf) = (u_int32)(((d_tmp) - (double)(r_i)) * FRAC); \
		} \
	} while (0)
#define M_LFPTOD(r_i, r_uf, d) 			/* l_fp to double */ \
	do { \
		register l_fp l_tmp; \
		\
		l_tmp.l_i = (r_i); \
		l_tmp.l_f = (r_uf); \
		if (l_tmp.l_i < 0) { \
			M_NEG(l_tmp.l_i, l_tmp.l_uf); \
			(d) = -((double)l_tmp.l_i + ((double)l_tmp.l_uf) / FRAC); \
		} else { \
			(d) = (double)l_tmp.l_i + ((double)l_tmp.l_uf) / FRAC; \
		} \
	} while (0)
#define DTOLFP(d, v)  M_DTOLFP((d), v.l_ui, v.l_uf)
#define LFPTOD(v, d)  M_LFPTOD(v.l_ui, v.l_uf, (d))

/*
 * l_fp / dd conversions
 */

#define M_LFPTODD(r_i, r_uf, d_i, d_f) 			/* l_fp to double */ \
	do { \
		register l_fp l_tmp; \
		\
		l_tmp.l_i = (r_i); \
		l_tmp.l_f = (r_uf); \
		if (l_tmp.l_i < 0) { \
			M_NEG(l_tmp.l_i, l_tmp.l_uf); \
			(d_i) = -((double)l_tmp.l_i + (int)(((double)l_tmp.l_uf) / FRAC)); \
			(d_f) = (((double)l_tmp.l_uf) / FRAC - (int)(((double)l_tmp.l_uf) / FRAC)); \
		} else { \
			(d_i) = (double)l_tmp.l_i + (int)(((double)l_tmp.l_uf) / FRAC); \
			(d_f) = (((double)l_tmp.l_uf) / FRAC - (int)(((double)l_tmp.l_uf) / FRAC)); \
		} \
	} while (0)
#define LFPTODD(v, d_i, d_f)  M_LFPTODD(v.l_ui, v.l_uf, (d_i), (d_f))

/*
 * ull / l_fp conversions
 */

#define M_ULLTOLFP(ull, r_ui, r_uf) /* unsigned long long to l_fp */ \
	do { \
		(r_ui) = (u_int32)((ull >> 32) & 0xffffffff); \
		(r_uf) = (u_int32)(ull & 0xffffffff); \
	} while(0)
#define M_LFPTOULL(r_ui, r_uf, ull) /* l_fp to unsigned long long */ \
	do { \
		(ull) = ((unsigned long long)(r_ui & 0xffffffff) << 32) | (r_uf & 0xffffffff); \
	} while(0)
#define ULLTOLFP(ull, v) M_ULLTOLFP((ull), v.l_ui, v.l_uf)
#define LFPTOULL(v, ull) M_LFPTOULL(v.l_ui, v.l_uf, (ull))

#define ULLTOD(ull, d) M_LFPTOD((u_int32)((ull >> 32) & 0xffffffff), (u_int32)(ull & 0xffffffff), (d))
#define DTOULL(d, ull) ()

//

struct burst_inst_struct {
	int min;
	int max;
	int step;
	double iatime_s;
	double lag_s;
	double lead_s;
	double B_s;                 /* 1B [s] */
	l_fp last_pkt_ts;
	unsigned int last_pkt_wlen;
	unsigned long burst_bytes;  /* collectors */
	unsigned long burst_packets;
	int cats;
// Debugging {{{
#ifdef __BURST_DEBUG_LAG_LEAD_MAX
	unsigned int initialized;
	unsigned long long lagmax;
	unsigned long long leadmax;
#endif
// }}}
};

static int burst_instance(mapidflib_function_instance_t *instance,
                          MAPI_UNUSED int fd,
                          MAPI_UNUSED mapidflib_flow_mod_t *flow_mod) {
	mapiFunctArg* fargs;
	int min, max, step;

	fargs = instance->args;
	min = getargint(&fargs);
	max = getargint(&fargs);
	step = getargint(&fargs);

	instance->def->shm_size = ((max-min)/step+2)*sizeof(burst_category_t);

// Debugging {{{
#ifdef __BURST_DEBUG
printf("Compiled with DEBUG flag\n");
#endif
#ifdef __BURST_VERBOSE
printf("Compiled with VERBOSE flag\n");
#endif
#ifdef __BURST_DEBUG_LAG_LEAD
printf("Compiled with DEBUG_LAG_LEAD flag\n");
#endif
#ifdef __BURST_DEBUG_LAG_LEAD_MAX
printf("Compiled with DEBUG_LAG_LEAD_MAX flag\n");
#endif
#ifdef __BURST_DEBUG_WARNINGS
printf("Compiled with DEBUG_WARNINGS flag\n");
#endif

#ifdef __BURST_DEBUG
printf("burst_instace(): min %d, max %d, step %d, shm_size %d\n", min, max, step, instance->def->shm_size);
#endif
// }}}

 return 0;
}

static int burst_init(mapidflib_function_instance_t *instance,
                      MAPI_UNUSED int fd) {
	struct burst_inst_struct *internal_data_ptr;
	mapiFunctArg* fargs;
	int min, max, step;
	int iatime, lag, lead;
	int link_speed;
////	l_fp B_frac_tmp;

	fargs = instance->args;
	min = getargint(&fargs);
	max = getargint(&fargs);
	step = getargint(&fargs);
	iatime = getargint(&fargs);
	lag = getargint(&fargs);
	lead = getargint(&fargs);
	link_speed = getargint(&fargs);

	if((instance->internal_data = malloc(sizeof(struct burst_inst_struct))) == NULL) {
		fprintf(stderr, "burst_init(): could not allocate internal data.\n");
		return MAPID_MEM_ALLOCATION_ERROR;
	}

	internal_data_ptr = (struct burst_inst_struct *) (instance->internal_data);
	internal_data_ptr->min = min;
	internal_data_ptr->max = max;
	internal_data_ptr->step = step;
	//DTOLFP((double)(iatime) / 1000000000, internal_data_ptr->iatime_s);
	//DTOLFP((double)(lag)    / 1000000000, internal_data_ptr->lag_s);
	//DTOLFP((double)(lead)   / 1000000000, internal_data_ptr->lead_s);
	internal_data_ptr->iatime_s = (double) iatime / 1000000000;
	internal_data_ptr->lag_s    = (double) lag    / 1000000000;
	internal_data_ptr->lead_s   = (double) lead   / 1000000000;
	internal_data_ptr->B_s = (double) 8 / ((double) link_speed * 1000000); // 1B [s]
////	//DTOULL(internal_data_ptr->B_s, internal_data_ptr->B_frac); // 1B [frac]
////	DTOLFP(internal_data_ptr->B_s, B_frac_tmp); // 1B [frac]
////	LFPTOULL(B_frac_tmp, internal_data_ptr->B_frac); // 1B [frac]

	memset(&internal_data_ptr->last_pkt_ts, 0, sizeof(l_fp));
	internal_data_ptr->last_pkt_wlen = 0;
	internal_data_ptr->burst_bytes = 0;
	internal_data_ptr->burst_packets = 0;
	internal_data_ptr->cats = (max - min) / step + 2 - 1;

// Debugging {{{
#ifdef __BURST_DEBUG_LAG_LEAD_MAX
internal_data_ptr->initialized = 0;
internal_data_ptr->lagmax  = 0;
internal_data_ptr->leadmax = (unsigned long long) -1;
#endif
#ifdef __BURST_DEBUG
//////printf("\n\n\niatime %012lu.%012lu (ntp) lag %012lu.%012lu (ntp) lead %012lu.%012lu (ntp)\n", internal_data_ptr->iatime_s.l_ui, internal_data_ptr->iatime_s.l_uf, internal_data_ptr->lag_s.l_ui, internal_data_ptr->lag_s.l_uf, internal_data_ptr->lead_s.l_ui, internal_data_ptr->lead_s.l_uf);
printf("iatime %23.12f lag %23.12f lead %23.12f\n", internal_data_ptr->iatime_s, internal_data_ptr->lag_s, internal_data_ptr->lead_s);
printf("link_speed: %u (mbps)\n", link_speed);
printf("1 B: %23.12f (sec)\n\n\n", internal_data_ptr->B_s);
#endif
// }}}

	return 0;
}

static int burst_process(mapidflib_function_instance_t *instance,
			MAPI_UNUSED unsigned char* dev_pkt,
			MAPI_UNUSED unsigned char* link_pkt,
			mapid_pkthdr_t* pkt_head) {

	struct burst_inst_struct *internal_data_ptr;
	int cat;

	// count with l_fp
	l_fp pkt_ts_min, pkt_ts_max, pkt_ts_exa, len_ts_min, len_ts_max, len_ts_exa;
	// store final values in ull
	unsigned long long pkt_ts_ull_min, pkt_ts_ull_max, pkt_ts_ull_exa;
	// gap
	unsigned long long gap_len_frac;
	double gap_len_s;
	unsigned long long gap_len_b;

// Debugging {{{
// just ascii art, not code
#ifdef __BURST_DEBUG
l_fp delta, pkt_ts, len_ts, assumed_ts;
double d_i, d_f;
#endif
#ifdef __BURST_DEBUG_LAG_LEAD
l_fp laglead;
#ifndef __BURST_DEBUG
l_fp len_ts, assumed_ts;
double d_i, d_f;
#endif
#endif
#ifdef __BURST_DEBUG_LAG_LEAD_MAX
unsigned long long assumed_ts_ull, len_ts_ull, laglead_ull;
#ifndef __BURST_DEBUG_LAG_LEAD
l_fp laglead;
#ifndef __BURST_DEBUG
l_fp len_ts;
double d_i, d_f;
#endif
#endif
#endif
// }}}

	internal_data_ptr = (struct burst_inst_struct *) (instance->internal_data);

	// count min / max ts

	// start with last_pkt_ts
	pkt_ts_max = internal_data_ptr->last_pkt_ts;
	pkt_ts_min = internal_data_ptr->last_pkt_ts;
	pkt_ts_exa = internal_data_ptr->last_pkt_ts;

	// add wlen, iatime, +-
  DTOLFP(internal_data_ptr->last_pkt_wlen * internal_data_ptr->B_s + internal_data_ptr->iatime_s - internal_data_ptr->lead_s, len_ts_min);
  DTOLFP(internal_data_ptr->last_pkt_wlen * internal_data_ptr->B_s + internal_data_ptr->iatime_s + internal_data_ptr->lag_s, len_ts_max);
  DTOLFP(internal_data_ptr->last_pkt_wlen * internal_data_ptr->B_s + internal_data_ptr->iatime_s, len_ts_exa);
  L_ADD(pkt_ts_min, len_ts_min);
  L_ADD(pkt_ts_max, len_ts_max);
  L_ADD(pkt_ts_exa, len_ts_exa);

// Debugging {{{
#ifdef __BURST_DEBUG_WARNINGS
unsigned long long lastullts;
LFPTOULL(internal_data_ptr->last_pkt_ts, lastullts);
if(pkt_head->ts == lastullts) printf("* OMG, same timestamp as previous. Deja vu or what? Timestamps does not seem to be very reliable.\n");
if(pkt_head->ts < lastullts) printf("* OMG^2, timestamp smaller than previous. Timestamps does not seem to be very reliable.\n");
#endif

#ifdef __BURST_DEBUG
printf(">>> [ pkt_head->wlen: %d (B) ]\n", pkt_head->wlen);

ULLTOLFP(pkt_head->ts, delta);
L_SUB(delta, internal_data_ptr->last_pkt_ts);
LFPTODD(delta, d_i, d_f);
printf("with delt/\\: %012lu.%012lu (ntp) == %010.0f + %.012f (sec)\n", delta.l_ui, delta.l_uf, d_i, d_f);

//////printf("count with me: %u * %023.012f = %023.012f a+ %023.012f = %023.012f ok???\n", internal_data_ptr->last_pkt_wlen, internal_data_ptr->B_s, internal_data_ptr->last_pkt_wlen * internal_data_ptr->B_s, internal_data_ptr->iatime_s, internal_data_ptr->last_pkt_wlen * internal_data_ptr->B_s + internal_data_ptr->iatime_s);
assumed_ts = internal_data_ptr->last_pkt_ts;
DTOLFP(internal_data_ptr->last_pkt_wlen * internal_data_ptr->B_s + internal_data_ptr->iatime_s, len_ts);
L_ADD(assumed_ts, len_ts);
LFPTODD(assumed_ts, d_i, d_f);
printf("assumed_ts=: %012lu.%012lu (ntp) == %010.0f + %.012f (sec)\n", assumed_ts.l_ui, assumed_ts.l_uf, d_i, d_f);

ULLTOLFP(pkt_head->ts, pkt_ts);
LFPTODD(pkt_ts, d_i, d_f);
printf("current_ts=: %012lu.%012lu (ntp) == %010.0f + %.012f (sec) %llu\n", pkt_ts.l_ui, pkt_ts.l_uf, d_i, d_f, pkt_head->ts);
//
//LFPTODD(pkt_ts_min, d_i, d_f);
//printf("          -: %012lu.%012lu (ntp) == %010.0f + %.012f (sec)\n", pkt_ts_min.l_ui, pkt_ts_min.l_uf, d_i, d_f);
//
//LFPTODD(pkt_ts_max, d_i, d_f);
//printf("          +: %012lu.%012lu (ntp) == %010.0f + %.012f (sec)\n", pkt_ts_max.l_ui, pkt_ts_max.l_uf, d_i, d_f);
#endif

#ifdef __BURST_DEBUG_LAG_LEAD
assumed_ts = internal_data_ptr->last_pkt_ts;
DTOLFP(internal_data_ptr->last_pkt_wlen * internal_data_ptr->B_s + internal_data_ptr->iatime_s, len_ts);
L_ADD(assumed_ts, len_ts);
ULLTOLFP(pkt_head->ts, laglead);
L_SUB(laglead, assumed_ts);
LFPTODD(laglead, d_i, d_f);
printf("so lag/lead: %012lu.%012lu (ntp) == %010.0f + %.012f (sec)\n", laglead.l_ui, laglead.l_uf, d_i, d_f);
#endif

#ifdef __BURST_DEBUG_LAG_LEAD_MAX
LFPTOULL(internal_data_ptr->last_pkt_ts, assumed_ts_ull);
DTOLFP(internal_data_ptr->last_pkt_wlen * internal_data_ptr->B_s + internal_data_ptr->iatime_s, len_ts);
LFPTOULL(len_ts, len_ts_ull);
assumed_ts_ull += len_ts_ull;

laglead_ull = pkt_head->ts - assumed_ts_ull;
if(pkt_head->ts >= assumed_ts_ull) { // lag
	if(laglead_ull > internal_data_ptr->lagmax) { // update
		if(internal_data_ptr->initialized == 0) { // first time
			internal_data_ptr->initialized = 1; // initialize
		}
		else { // update
			internal_data_ptr->lagmax = laglead_ull;
ULLTOLFP(laglead_ull, laglead);
LFPTODD(laglead, d_i, d_f);
printf("lagmax     : %012lu.%012lu (ntp) == %010.0f + %.012f (sec)\n", laglead.l_ui, laglead.l_uf, d_i, d_f);
		}
	}
}
else { // lead
	if(laglead_ull < internal_data_ptr->leadmax) { // update
		if(internal_data_ptr->initialized == 0) { // first time
			internal_data_ptr->initialized = 1; // initialize
		}
		else {
			internal_data_ptr->leadmax = laglead_ull;
ULLTOLFP(laglead_ull, laglead);
LFPTODD(laglead, d_i, d_f);
printf("leadmax    : %012lu.%012lu (ntp) == %010.0f + %.012f (sec)\n", laglead.l_ui, laglead.l_uf, d_i, d_f);
		}
	}
}
#endif
// }}}

	// resolve bursts

	LFPTOULL(pkt_ts_min, pkt_ts_ull_min);
	LFPTOULL(pkt_ts_max, pkt_ts_ull_max);
	LFPTOULL(pkt_ts_exa, pkt_ts_ull_exa);

	// not burst
	if(pkt_head->ts < pkt_ts_ull_min || pkt_head->ts > pkt_ts_ull_max) {

		// count measurement into results
		if(internal_data_ptr->burst_bytes < (unsigned long) internal_data_ptr->min) {

// Debugging {{{
#ifdef __BURST_VERBOSE
printf("process: I am sed :-( I wish I have [0.x] to save this burst into.\n");
#endif
// }}}

			cat = 0;
		}
		else cat = ((internal_data_ptr->burst_bytes - internal_data_ptr->min) / internal_data_ptr->step) + 1; // +1: category 0 is reserved for <0, min>

		if(cat > internal_data_ptr->cats) {

// Debugging {{{
#ifdef __BURST_VERBOSE
printf("process: I am sed :-( I wish I have [%d] to save this burst into.\n", cat);
#endif
// }}}

			cat = internal_data_ptr->cats;
		}

		((burst_category_t *)instance->result.data)[cat].bytes   += internal_data_ptr->burst_bytes;
		((burst_category_t *)instance->result.data)[cat].packets += internal_data_ptr->burst_packets;
		if(internal_data_ptr->burst_bytes > 0) // not the very first packet
		((burst_category_t *)instance->result.data)[cat].bursts++;

// Debugging {{{
#ifdef __BURST_VERBOSE
printf("process: save [%d / %d] += %lu B (= %lu B), += %lu pkts (= %lu pkts), +1 burst (= %lu bursts)\n", cat, internal_data_ptr->cats, internal_data_ptr->burst_bytes, ((burst_category_t *)instance->result.data)[cat].bytes, internal_data_ptr->burst_packets, ((burst_category_t *)instance->result.data)[cat].packets, ((burst_category_t *)instance->result.data)[cat].bursts);
#endif
// }}}
		
		// and start new measurement
		internal_data_ptr->burst_bytes = 0;   // reset collectors
		internal_data_ptr->burst_packets = 0;

		// NEW: store inter-burst gap size too

		if(internal_data_ptr->last_pkt_wlen) { // if not first packet

			if(pkt_head->ts > pkt_ts_ull_exa) {
				gap_len_frac = pkt_head->ts - pkt_ts_ull_exa;
				ULLTOD(gap_len_frac, gap_len_s);
				gap_len_b = (unsigned long long) (gap_len_s / internal_data_ptr->B_s);
			}
			else gap_len_b = 0;

			if(gap_len_b < (unsigned) internal_data_ptr->min) {
				cat = 0;
			} else cat = ((gap_len_b - internal_data_ptr->min) / internal_data_ptr->step) + 1; // +1: category 0 is reserved for <0, min>

			if(cat > internal_data_ptr->cats) {
				cat = internal_data_ptr->cats;
			}

			((burst_category_t *)instance->result.data)[cat].gap_bytes += gap_len_b;
			if(internal_data_ptr->burst_bytes > 0) // not the very first packet
			((burst_category_t *)instance->result.data)[cat].gaps++;
		}

	}
	else { // if one bursts, show goes on

// Debugging {{{
#ifdef __BURST_VERBOSE
printf("process: collect [x] (BURST detected)\n");
#endif
// }}}

	}

	// count current into collector
	internal_data_ptr->burst_bytes += (unsigned long) pkt_head->wlen;
	internal_data_ptr->burst_packets++;

	// save pktinfo for next generation
	ULLTOLFP(pkt_head->ts, internal_data_ptr->last_pkt_ts);
	internal_data_ptr->last_pkt_wlen = pkt_head->wlen;

	return 1;
}

static int burst_reset(mapidflib_function_instance_t* instance) {
	struct burst_inst_struct *internal_data_ptr;
	internal_data_ptr = (struct burst_inst_struct *) (instance->internal_data);

	L_SUB(internal_data_ptr->last_pkt_ts, internal_data_ptr->last_pkt_ts);
	internal_data_ptr->burst_bytes = 0;
	internal_data_ptr->burst_packets = 0;
	memset(instance->result.data, 0, instance->def->shm_size);

	return 0;
}

static int burst_cleanup(mapidflib_function_instance_t *instance) {
	free(instance->internal_data);
  return 0;
}

static mapidflib_function_def_t finfo = {
  "", //libname
  "BURST", //name
  "Returns the histogram of bursts.\nReturn value: array of unsigned long.", //descr
  "iiiiiii", //argdescr
  MAPI_DEVICE_ALL, //devoid
  MAPIRES_SHM, //Method for returning results
  0, //shm size. Set by instance.
  0, //modifies_pkts
  0, //filters packets
  MAPIOPT_NONE, //Optimization
  burst_instance, //
  burst_init,
  burst_process,
  NULL, //get_result,
  burst_reset, //reset
  burst_cleanup, //cleanup
  NULL, //client_init
  NULL, //client_read_result
  NULL  //client_cleanup
};

mapidflib_function_def_t* burst_get_funct_info();

mapidflib_function_def_t* burst_get_funct_info() {
  return &finfo;
}

// end of burst.c

/* vim: set foldmethod=marker foldmarker=\ {{{,\ }}} foldclose= foldcolumn=0 : */
