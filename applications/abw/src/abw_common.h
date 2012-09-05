/*
 * Copyright (c) 2006, CESNET
 * All rights reserved.
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the company nor the names of its contributors 
 *       may be used to endorse or promote products derived from this 
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY 
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
 * THE COMPANY OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; 
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 *
 */

#ifndef __ABW_COMMON_H
#define __ABW_COMMON_H

#define _XOPEN_SOURCE /* glibc2 needs this */
#include <time.h>
#include <sys/time.h>

#include "abw_conf.h"

#define MAX_COMMAND					256
#define MAX_HOSTNAME_INTERFACE	256

typedef struct {
	char *protocol;
	char *track_function;
} tracked_protocol_t;

typedef struct {
	char *protocol;
	char *filter_string;
} protocol_t;

/* 
 * Runtime properties of one MAPI flow
 */
typedef struct flow_struct {
  measurement_t *measurement;
  char *protocol;
  
  char *header_filter;	/* compiled header filter including protocols */
  int tracked_protocol;	/* index into tracked_protocols[] increased by 1 */

  int fd;               	/* flow file descriptor */

  int interface_fid;			/* fid for INTERFACE */
  int bpf_filter_fid;		/* fid for BPF_FILTER */
  int track_function_fid;	/* fid for a tracklib function */
  int sample_fid;		/* fid for SAMPLE */
  int str_search_fid;		/* fid for STR_SEARCH */
  int pkt_counter_fid;		/* fid for PKT_COUNT */
  int byte_counter_fid;		/* fid for BYTE_COUNT */

  unsigned long long pkt_counter[MAX_SUBJECTS];	 /* packets from PKT_COUNTER */
  unsigned long long byte_counter[MAX_SUBJECTS]; /* bytes from BYTE_COUNTER */

  char *rrd_filename;
  unsigned long long pkt_ts[MAX_SUBJECTS];	/* time of the previous result */
  unsigned long long byte_ts[MAX_SUBJECTS];	/* time of the previous result */
  time_t rrd_ts;										/* time of previous RRD update */

  struct flow_run_struct *next;
} flow_t;

flow_t *new_flow(void);

int protocol_filter(char *header_filter, char *protocol, int mpls, int vlan,
	char **new_header_filter);

int get_local_hostname(char **hostname);

int timestamp_diff(struct timeval *tv_start, struct timeval *tv_stop);

int continue_as_daemon(void);

#endif
