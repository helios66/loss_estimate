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
#include <setjmp.h>
#include <stdarg.h>
#include <string.h>

#include "utils.h"

#include "bpfcompiler.h"
#include "bpf_compile.h"
#include "bpf_node.h"


/* Locals */
/*static*/ jmp_buf bpf_error_jmp;
/*static*/ int bpf_error_set = 0;
/*static*/ char *bpf_errbuf;

static node_t *root;

/* String list */
static string_t *string_head = NULL;


/*
 * error handling
 */
void bpf_error(const char *fmt, ...)
{
    va_list ap;

    if (!bpf_error_set) {
        fprintf(stderr, "bpfcompiler internal error: error function not set!\n");
        exit(-1);
    }
    va_start(ap, fmt);
    if (bpf_errbuf != NULL) {
            (void)vsnprintf(bpf_errbuf, BPF_ERRBUF_SIZE, fmt, ap);
    }
    va_end(ap);
    longjmp(bpf_error_jmp, 1);
}


/*
 * syntax error
 */
inline void syntax()
{
    bpf_error("syntax error in filter expression");
}

/*
 * A strdup whose allocations are freed after code generation is over.
 */
char *sdup(register const char *s)
{
    string_t *tmp;

    tmp = xmalloc(sizeof(string_t));
    tmp->string = strdup(s);
    tmp->next = string_head;
    string_head = tmp;
    return tmp->string;
}

/*
 * Free memory allocations
 */
void bpf_compile_cleanup(void)
{
    // delete strings
    string_t *tmp;

    while (string_head != NULL) {
        /* Free allocated string */
        free(string_head->string);
        tmp = string_head->next;
        /* Free string_head itself */
        free(string_head);
        string_head = tmp;
    }

    // lex cleanup
    lex_cleanup();
}

/*
 * Parsing was finished.
 */
void finish_parse(node_t *b)
{
    root = b;
}

/*
 * Compile bpf filter
 */
int bpf_compile(node_t **tree_root, char *errbuf, char *buf, int with_sctp_proto)
{
        extern int n_errors, gen_sctp_proto;

        gen_sctp_proto = with_sctp_proto;

        bpf_errbuf = errbuf;

        bpf_error_set = 1;
        if (setjmp(bpf_error_jmp)) {
            //free_nodes();
            bpf_compile_cleanup();
            bpf_error_set = 0;
            return (-1);
        }

        lex_init(buf ? buf : "");
        (void)bpf_parse();

        if (n_errors)
                syntax();

        if (root == NULL)
            ERROR("null root");

        *tree_root = root;

        bpf_compile_cleanup();
        bpf_error_set = 0;
        return (0);
}
