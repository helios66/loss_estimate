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


#ifndef _BPF_NODE_H_
#define _BPF_NODE_H_

#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

#define Q_CODE  1
#define Q_TYPE  2
#define Q_FLAGS  3

typedef unsigned int u_int_t;

typedef enum { binary_type, link_type, host_type, ehost_type, mpls_type, vlan_type, proto_type, port_type, portrange_type, type_type, ethertype_type } node_type;

typedef struct binary_node {
    struct node *left, *right;
    int type;
} binary_node_t;

typedef struct link_node {
    u_int_t offset;
    u_int32_t proto;
} link_node_t;

typedef struct host_node {
    u_int32_t addr;
    u_int32_t mask;
    int dir;
    u_int_t offset;
} host_node_t;

typedef struct ehost_node {
    unsigned char eaddr[6];
    unsigned char mask[6];
    int dir;
} ehost_node_t;

typedef struct mpls_node {
    u_int32_t label;
    u_int32_t mask;
} mpls_node_t;

typedef struct vlan_node {
    u_int32_t id;
    u_int32_t mask;
} vlan_node_t;

typedef struct proto_node {
    u_int32_t proto;
} proto_node_t;

typedef struct port_node {
    int port;
    int offset;
    int dir;
} port_node_t;

typedef struct portrange_node {
    int port1;
    int port2;
    int offset;
    int dir;
} portrange_node_t;

typedef struct type_node {
    int proto;
    int type;
    int value;
} type_node_t;

typedef struct ethertype_node {
    short int type;
} ethertype_node_t;

typedef struct node {
    node_type type;
    struct node *next;

    union {
        binary_node_t binary_node;
        link_node_t link_node;
        host_node_t host_node;
        ehost_node_t ehost_node;
        mpls_node_t mpls_node;
        vlan_node_t vlan_node;
        proto_node_t proto_node;
        port_node_t port_node;
        portrange_node_t portrange_node;
        type_node_t type_node;
        ethertype_node_t ethertype_node;
    };
} node_t;


node_t *new_and_node(node_t *b0, node_t *b1);
node_t *new_or_node(node_t *b0, node_t *b1);
node_t *new_link_node(int offset, u_int32_t proto);
node_t *new_host_node(u_int32_t addr, u_int32_t mask, int dir, u_int_t offset);
node_t *new_ehost_node(unsigned char *eaddr, unsigned char *mask, int dir);
node_t *new_mpls_node(unsigned int label);
node_t *new_vlan_node(unsigned int vlan_num);
node_t *new_proto_node(u_int32_t proto);
node_t *new_port_node(int port, int offset, int dir);
node_t *new_portrange_node(int port1, int port2, int offset, int dir);
node_t *new_type_node(int proto, int type, int value);
node_t *new_ethertype_node(short int type);

void free_nodes(void);
node_t *duplicate_tree(node_t *b);
void print_node(FILE *stream, node_t *b);

node_t **transform_tree(node_t *b, int *count);

#endif /* _BPF_NODE_H_ */
