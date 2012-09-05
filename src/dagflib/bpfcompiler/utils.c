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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "utils.h"
#include "bpf_compile.h"

/*void *xmalloc(size_t size)
{
    register void *value = malloc(size);
    if (value == 0)
        FATAL("malloc");
    return value;
}

void *xrealloc(void *ptr, size_t size)
{
    register void *value = realloc(ptr, size);
    if (value == 0)
        FATAL("Error: realloc");
    return value;
}
*/
//void *xfree(void *ptr)
//{
//    free(ptr);
//}

void dsnew(dstring_t *s)
{
    s->size = MIN_XSTRING_SIZE;
    s->nchars = 0;
    s->string = (char *) xmalloc(MIN_XSTRING_SIZE);
    s->string[0] = 0;
}

void dsfree(dstring_t *s)
{
    free(s->string);
    s->size = 0;
    s->nchars = 0;
}

void dsclear(dstring_t *s)
{
    s->nchars = 0;
}

int dsprintf(dstring_t *s, const char *fmt, ...)
{
    int retval;
    /* Calculate the free size of buffer */
    int size = s->size - s->nchars;
    va_list ap;

    va_start(ap, fmt);
    /* Try to print in the buffer */
    retval = vsnprintf(s->string + s->nchars, size, fmt, ap);
    va_end(ap);

    if (retval >= size) {
        /* Reallocate small buffer */
        if (retval < MIN_XSTRING_SIZE) retval = MIN_XSTRING_SIZE;
        size = s->size + retval + 1;
        s->string = (char *) xrealloc(s->string, size);
        s->size = size;
        size = size - s->nchars;

        va_start(ap, fmt);
        /* Try again */
        retval = vsnprintf(s->string + s->nchars, size, fmt, ap);
        va_end(ap);

//        if (retval >= size) FATAL("dsprintf");
    }
    s->nchars += retval;

    /* Return the number of written characters */
    return retval;
}

char *dsstrdup(dstring_t *s)
{
    return strdup(s->string);
}

char *dsgets(dstring_t *s)
{
    return s->string;
}

