/*
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. Neither the name of the Company nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'', AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COMPANY OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _BPFCOMPILER_H_
#define _BPFCOMPILER_H_

#include <stdio.h>

#define BPF_ERRBUF_SIZE 256

/*
 * Filter structures
 */
typedef struct dagdsm_bpf_filter dagdsm_bpf_filter_t;

typedef enum { BALANCE_NONE, BALANCE_CRC32, BALANCE_PARITY, BALANCE_INTERFACE } bal_t;

/*
 * Compile bpf filter functions
 */
dagdsm_bpf_filter_t *dagdsm_bpf_compile(dagdsm_bpf_filter_t *filter, char *buf, int index, char *errbuf);

/*
 * Write filter to the text format
 */
char *dagdsm_bpf_xprintf(dagdsm_bpf_filter_t *bpf_filter, int always_match, 
			 int num_dag_interfaces, char *errbuf);

/* 
 * Other functions
 */
unsigned int dagdsm_bpf_get_last_usage_mask(dagdsm_bpf_filter_t *bpf_filter);

/*
 * Returns the number of hardware filters that shall be used
 * for entire configuration.
 */
int dagdsm_bpf_get_filter_count(dagdsm_bpf_filter_t *bpf_filter);

/*
 * Free resources allocated by the filter
 */
void dagdsm_bpf_free(dagdsm_bpf_filter_t *filter);

#endif /* _BPFCOMPILER_H_ */
