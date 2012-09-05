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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>

#include "utils.h"
#include "bpfcompiler.h"

#define FATAL(str, rest...) fatal("internal error in %s:%d: " str "\n", __FILE__, __LINE__, ## rest)

void fatal(const char *fmt, ...)
        __attribute__((noreturn, format (printf, 1, 2)));

void fatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(-1);
}

void usage(char *progname)
{
    fprintf(stderr, "Usage: %s --num-ports=<num-ports> [--max-filters=<number>] [--always-match]\n", progname);    
    exit(100);
}

void parse_args(int argc, char **argv, int *max_filters, int *always_match, int *num_ports)
{
    int i;
    *always_match = 0;
    *max_filters = INT_MAX;
    *num_ports = 0;

    for (i=1; i<argc; i++) {
    	if (!strncmp("--num-ports=", argv[i], 12)) {
            *num_ports = atoi(argv[i] + 12);
    	} else if (!strncmp("--max-filters=", argv[i], 14)) {
            *max_filters = atoi(argv[i] + 14);
            if (*max_filters < 1)
                usage(argv[0]);
        } else if (!strcmp("--always-match", argv[i])) {
            (*always_match)++;
        } else if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            usage(argv[0]);
        } else
            fatal("%s: Unknown or misformatted parameter '%s'. Use --help for help.\n", argv[0], argv[i]);
    }
    if (*num_ports <= 0)
    	usage(argv[0]);
}

int main(int argc, char **argv)
{
    char errbuf[BPF_ERRBUF_SIZE], inbuf[4096], *output;
    int lineno = 0, max_filters, always_match, filter_count, num_ports;
    dagdsm_bpf_filter_t *filter = NULL;

    parse_args(argc, argv, &max_filters, &always_match, &num_ports); 

    while (fgets(inbuf, sizeof(inbuf), stdin)) {
        char *p = strchr(inbuf, '\n'); 

        lineno++;
        if (!p)
            fatal("%s: Fatal error, the length of input line %d is above %u bytes.\n", argv[0], lineno, sizeof(inbuf)-1);
        
        *p = '\0';
        if (inbuf[0] == '\0')
            continue;

        /* Compile BPF filter */
        if ((filter = dagdsm_bpf_compile(filter, inbuf, lineno, errbuf)) == NULL)
            fatal("%s: Compilation error on input line %d: %s\n", argv[0], lineno, errbuf);

        BPF_DEBUG_CMD(fprintf(stderr, "line %d filtermask 0x%08x\n", lineno, dagdsm_bpf_get_last_usage_mask(filter)));
    }

    filter_count = dagdsm_bpf_get_filter_count(filter);
    
    if (filter_count > max_filters)
        fatal("%s: The number of filters needed (%d) exceeds the given limit (%d).\n", argv[0], filter_count, max_filters);

    /* Write the filter to DAGDSM configuration output file. */
    output = dagdsm_bpf_xprintf(filter, always_match, num_ports, errbuf);

    /* Free resources allocated for the filter. */
    if (filter != NULL)
        dagdsm_bpf_free(filter);

    if (output) 
    	printf(output);
    else
    	fatal("%s: Compilation error on input line %d: %s\n", argv[0], lineno, errbuf);

    free(output);

    return EXIT_SUCCESS;
}
