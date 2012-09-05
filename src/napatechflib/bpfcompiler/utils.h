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

#ifndef _UTILS_H_
#define _UTILS_H_

#define MIN_XSTRING_SIZE 200

#define CERROR() ERROR("compilation error [%s:%d]", __FILE__, __LINE__)

#if 0
#  define BPF_DEBUG_CMD(code) code
#else
#  define BPF_DEBUG_CMD(code)
#endif

typedef struct dstring {
    int size;
    int nchars;
    char *string;
} dstring_t;

#define xmalloc malloc
#define xrealloc realloc

/*void *xmalloc (size_t size);
void *xrealloc (void *ptr, size_t size);*/
//void *xfree(void *ptr);

void dsnew(dstring_t *s);
void dsfree(dstring_t *s);
void dsclear(dstring_t *s);
int dsprintf(dstring_t *s, const char *fmt, ...)
        __attribute__ ((format (printf, 2, 3)));
char *dsstrdup(dstring_t *s);
char *dsgets(dstring_t *s);

#endif /* _UTILS_H_ */
