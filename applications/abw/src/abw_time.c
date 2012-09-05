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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "abw_common.h"
#include "abw_time.h"

int abw_next_timestamp(struct timeval *interval,
							  struct timeval *next,
							  struct timeval *wait) {

	struct timeval current;
	static struct timeval last;

	if (interval==NULL ||
		 interval->tv_sec<0 || interval->tv_usec<0 || 
		 (interval->tv_sec==0 && interval->tv_usec==0) ||
		 interval->tv_usec>=1000000) {
		fprintf(stderr, "%s: incorrect arguments\n", __func__);
		return -1;
	}

	if (gettimeofday(&current, NULL)<0) {
		fprintf(stderr, "%s: gettimeofday() failed\n", __func__);
		return -1;
	}

	if (last.tv_sec) { /* this is not a first timestamp to compute */
		last.tv_sec+=interval->tv_sec;
		last.tv_usec+=interval->tv_usec;
	}

	/* If this is the first timestamp to compute or if the computed
		timestamp is in the past then compute a new timestamp as the
		earliest future time rounded to given interval */
	if (!last.tv_sec || 
		 last.tv_sec < current.tv_sec ||
		 (last.tv_sec == current.tv_sec && last.tv_usec < current.tv_usec)) {

		printf("%s: Next interval missed, will wait until nearest future interval\n", __func__);

		if (interval->tv_sec)
			last.tv_sec=(current.tv_sec / interval->tv_sec * interval->tv_sec) 
							+ interval->tv_sec;
		else
			last.tv_sec=current.tv_sec;

		if (interval->tv_usec)
			last.tv_usec=(current.tv_usec / interval->tv_usec * interval->tv_usec) 
							+ interval->tv_usec;
		else
			last.tv_usec=0;
	}

	if (last.tv_usec>=1000000) {
		last.tv_sec++;
		last.tv_usec-=1000000;
	}

	if (next!=NULL) {
		next->tv_sec=last.tv_sec;
		next->tv_usec=last.tv_usec;
	}

	if (wait!=NULL) {

		if ((last.tv_sec - current.tv_sec) > 1) {
			wait->tv_sec=last.tv_sec - current.tv_sec - 1;
			wait->tv_usec=(1000000-current.tv_usec) + last.tv_usec;
		}
		else if (last.tv_sec > current.tv_sec) {
			wait->tv_sec=0;
			wait->tv_usec=(1000000-current.tv_usec) + last.tv_usec;
		}
		else {
			wait->tv_sec=0;
			wait->tv_usec=last.tv_usec - current.tv_usec;
		}

		if (wait->tv_usec>=1000000) {
			wait->tv_sec++;
			wait->tv_usec-=1000000;
		}
	}

	return -1;
} /* abw_next_timestamp() */
