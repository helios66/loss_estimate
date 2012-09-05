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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpfcompiler.h"

void test_dagdsm(char *bpf, int always_match, int num_ports)
{
    dagdsm_bpf_filter_t *filter;
    char *output, errbuf[BPF_ERRBUF_SIZE];

    /* Compile BPF filter */
    if ((filter = dagdsm_bpf_compile(NULL, bpf, 0, errbuf)) == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return;
    }

    fprintf(stderr, "DAG DSM filter:\n");

    /* Translate filter to DAGDSM configuration. */
    output = dagdsm_bpf_xprintf(filter, always_match, num_ports, errbuf);

    /* Free resources allocated for the filter */
    dagdsm_bpf_free(filter);

    if (output)
        printf(output);
    else
        fprintf(stderr, "Error: %s\n", errbuf);
    
    free(output);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage:\n"
               "\t%s --num-ports=<num-ports> [--always-match] \"BPF EXPRESSION\"\n"
               "WARNING: Option order is important!\n",
                argv[0]);
        return 100;
    }

        int bpf_idx = 1, always_match, num_ports = 0;

    	if (!strncmp(argv[bpf_idx], "--num-ports=", 12)) {
                num_ports = atoi(argv[bpf_idx] + 12);
                bpf_idx++;
    	}
    	if (num_ports <= 0) {
    		fprintf(stderr, "Must specify the number of DAG ports (interfaces) greater that zero.\n");
    		exit(1);
    	}

        always_match = !strcmp(argv[bpf_idx], "--always-match");
        if (always_match) bpf_idx++;

        fprintf(stderr, "BPF: %s\n", argv[bpf_idx]);

        test_dagdsm(argv[bpf_idx], always_match, num_ports);
    return 0;
}
