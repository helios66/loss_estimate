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

#include "utils.h"
#include "bpf_node.h"
#include "bpf_compile.h"
#include "bpf_pcap.h"

/*
 * (src port 30 and (dst port 40 or 50))
 *
 */
/*
                                                                            AND
                                 +-------------------------------------------+--------------------------------------------+
                                 |                                                                                        |
                                AND                                                                                      OR
             +-------------------+---------------------+                                            +---------------------+-------------------------+
            IP                                         OR                                          AND                                             AND
                                            +----------+----------+                     +-----------+----------+                        +-----------+-----------+
                                           AND                    OR                   IP                      OR                      IP                      OR
                                    +-------+-------+      +---------------+                           +-------+-------+                             +---------+---------+
                                  SCTP              30    AND             AND                         AND              OR                           AND                  OR
                                                        +--+--+         +--+--+                     +--+---+       +----+----+                  +----+----+         +-----+----+
                                                       TCP    30       UDP   30                    SCTP   40      AND       AND                SCTP       50       AND         AND
                                                                                                                +--+---+  +--+---+                               +--+--+     +--+--+
                                                                                                               TCP    40  UDP    40                             TCP    50   UDP    50
*/

static int transform(node_t *root, int *dnf);

/*
 * Create DNF tree
 */

static int transform(node_t *root, int *dnf)
{
    node_t *left, *right;
    node_t *a, *b;
    int trans = 0;

    /* only for binary type */
    if (root->type != binary_type) return 0;

    left = root->binary_node.left;
    right = root->binary_node.right;

    a = left;
    b = right;

    /* only 'and' need transformation */
    if (root->binary_node.type == Q_AND) {
        if (left->type == binary_type && left->binary_node.type == Q_OR) {
            /* left 'or' transformation */
            b = new_and_node(left->binary_node.right, duplicate_tree(right));

            //a = left;
            a->binary_node.type = Q_AND;
            //a->binary_node.left = left->binary_node.left;;
            a->binary_node.right = right;

            trans++;
        } else if (right->type == binary_type && right->binary_node.type == Q_OR) {
            /* right 'or' transformation */
            a = new_and_node(duplicate_tree(left), right->binary_node.left);

            //b = right;
            b->binary_node.type = Q_AND;
            b->binary_node.left = left;
            //b->binary_node.right = right->binary_node.right;
            trans++;
        };

        if (trans) {
            /* setup the root */
            root->binary_node.type = Q_OR;
            root->binary_node.left = a;
            root->binary_node.right = b;
        }
    } else (*dnf)++;  /* it's 'or', increase dnf */

    /* make recursive tramsformation */
    trans += transform(a, dnf);
    trans += transform(b, dnf);

    return trans;
}

static void dnf_list(node_t *b, node_t **list, int *i)
{
    if (b->type == binary_type && b->binary_node.type == Q_OR) {
        dnf_list(b->binary_node.left, list, i);
        dnf_list(b->binary_node.right, list, i);
        return;
    }
    list[*i] = b;
    (*i)++;
}

node_t **transform_tree(node_t *b, int *count)
{
    int i = 0;
    int dnf = 1;
    node_t **list;

    BPF_DEBUG_CMD(fprintf(stderr, "transform_tree\n"));

    while (transform(b, &dnf)) {
        i++;
        dnf = 1;
    }

    BPF_DEBUG_CMD(fprintf(stderr, "transformation cycles: %u, dnf deep: %u\n", i, dnf));

    list = xmalloc(sizeof(node_t) * dnf);

    *count = 0;
    dnf_list(b, list, count);
    if (*count != dnf) {
        BPF_DEBUG_CMD(fprintf(stderr, "transform_tree error, bad dnf.\n"));
        return NULL;
    }

    BPF_DEBUG_CMD(fprintf(stderr, "transformation completed\n"));
    return list;
}
