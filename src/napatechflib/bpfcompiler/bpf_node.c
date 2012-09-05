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

#include "utils.h"
#include "bpf_node.h"
#include "bpf_compile.h"
#include "bpf_pcap.h"

node_t *head = NULL;

static node_t *new_node(node_type type);
static node_t *new_binary_node(int type, node_t *b0, node_t *b1);

static node_t *new_node(node_type type)
{
    node_t *tmp;

    tmp = xmalloc(sizeof(node_t));
    tmp->type = type;
    tmp->next = head;
    head = tmp;

    return tmp;
}

void free_nodes(void)
{
    node_t *tmp;

    while (head != NULL) {
      tmp = head->next;
      free(head);
      head = tmp;
    }
}


static node_t *new_binary_node(int type, node_t *b0, node_t *b1)
{
    node_t *n = new_node(binary_type);
    n->binary_node.left = b0;
    n->binary_node.right = b1;
    n->binary_node.type = type;
    return n;
}


/*
 * gen_and
 */
node_t *new_and_node(node_t *b0, node_t *b1)
{
    return new_binary_node(Q_AND, b0, b1);
}

/*
 * gen_or
 */
node_t *new_or_node(node_t *b0, node_t *b1)
{
    return new_binary_node(Q_OR, b0, b1);
}

/*
 * gen_linktype
 */
node_t *new_link_node(int offset, u_int32_t proto)
{
    node_t *n = new_node(link_type);
    n->link_node.offset = offset;
    n->link_node.proto = proto;
    return n;
}

/*
 * gen_hostop
 */
node_t *new_host_node(u_int32_t addr, u_int32_t mask, int dir, u_int_t offset)
{
    node_t *n = new_node(host_type);
    n->host_node.addr = addr;
    n->host_node.mask = mask;
    n->host_node.dir = dir;
    n->host_node.offset = offset;
    return n;
}

/*
 * gen_ehostop
 */
node_t *new_ehost_node(unsigned char *eaddr, unsigned char *mask, int dir)
{
    int i;
    node_t *n = new_node(ehost_type);
    for (i=0; i<6;) {
       if (*eaddr != 0x3A) {
           n->ehost_node.eaddr[i] = *eaddr;
           i++;
       }
       eaddr++;
    }
    for (i=0; i<6;) {
       if (*eaddr != 0x3A) {
           n->ehost_node.mask[i] = *mask;
           i++;
       }
       mask++;
    }
    n->ehost_node.dir = dir;
    return n;
}

/*
 * gen_mpls
 */
node_t *new_mpls_node(unsigned int label)
{
    node_t *n = new_node(mpls_type);
    n->mpls_node.label = label;
    n->mpls_node.mask = 0x000FFFFF; //20 bits
    return n;
}

/*
 * gen_vlan
 */
node_t *new_vlan_node(unsigned int vlan_num)
{
    node_t *n = new_node(vlan_type);
    n->vlan_node.id = vlan_num;
    n->vlan_node.mask = 0x00000FFF; //12 bits
    return n;
}

/*
 * part of gen_protop
 */
node_t *new_proto_node(u_int32_t proto)
{
    node_t *n = new_node(proto_type);
    n->proto_node.proto = proto;
    return n;
}

/*
 * gen_port
 */
node_t *new_port_node(int port, int offset, int dir)
{
    node_t *n = new_node(port_type);
    n->port_node.port = port;
    n->port_node.offset = offset;
    n->port_node.dir = dir;
    return n;

}

/*
 * gen_portrange
 */
node_t *new_portrange_node(int port1, int port2, int offset, int dir)
{
    node_t *n = new_node(portrange_type);
    n->portrange_node.port1 = port1;
    n->portrange_node.port2 = port2;
    n->portrange_node.offset = offset;
    n->portrange_node.dir = dir;
    return n;
}

/*
 * gen_type
 */
node_t *new_type_node(int proto, int type, int value)
{
    node_t *n = new_node(type_type);
    n->type_node.proto = proto;
    n->type_node.type = type;
    n->type_node.value = value;
    return n;
}

/*
 * gen_ethertype ??
 */
node_t *new_ethertype_node(short int type)
{
    node_t *n = new_node(ethertype_type);
    n->ethertype_node.type = type;
    return n;
}

/*
 * ----------------------------------------------------------------------------
 */

/*
 * maybe it's ok only to duplicate binary node
 */
node_t *duplicate_tree(node_t *b)
{
    switch(b->type) {
        case binary_type:
            return new_binary_node(b->binary_node.type, duplicate_tree(b->binary_node.left), duplicate_tree(b->binary_node.right));
        case link_type:
            return new_link_node(b->link_node.offset, b->link_node.proto);
        case host_type:
            return new_host_node(b->host_node.addr, b->host_node.mask, b->host_node.dir, b->host_node.offset);
        case ehost_type:
            return new_ehost_node(b->ehost_node.eaddr, b->ehost_node.mask, b->ehost_node.dir);
        case mpls_type:
            return new_mpls_node(b->mpls_node.label);
        case vlan_type:
            return new_vlan_node(b->vlan_node.id);
        case proto_type:
            return new_proto_node(b->proto_node.proto);
        case port_type:
            return new_port_node(b->port_node.port, b->port_node.offset, b->port_node.dir);
        case portrange_type:
            return new_portrange_node(b->portrange_node.port1, b->portrange_node.port2, b->portrange_node.offset, b->portrange_node.dir);
        case type_type:
            return new_type_node(b->type_node.proto, b->type_node.type, b->type_node.value);
        case ethertype_type:
            return new_ethertype_node(b->ethertype_node.type);
        default:
            ERROR("duplicate tree error");
    }
}

/*
 * ----------------------------------------------------------------------------
 */

static void print_binary_node(FILE *stream, node_t *b)
{
    fprintf(stream, "(");
    print_node(stream, b->binary_node.left);
    switch (b->binary_node.type) {
        case Q_AND:
            fprintf(stream, " AND ");
            break;
        case Q_OR:
            fprintf(stream, " OR ");
            break;
        default:
            ERROR("BIN ERROR");
    }
    print_node(stream, b->binary_node.right);
    fprintf(stream, ")");
}

static void printf_dir(FILE *stream, int dir)
{
    switch(dir) {
        case Q_SRC:
            fprintf(stream, "SRC");
            break;
        case Q_DST:
            fprintf(stream, "DST");
            break;
        case Q_DEFAULT:
            fprintf(stream, "DEFAULT");
            break;
        case Q_UNDEF:
            fprintf(stream, "UNDEF");
            break;
        case Q_OR:
        case Q_AND:
        default:
            ERROR("DIR ERROR");
    }
}


static void print_link_node(FILE *stream, node_t *b)
{
    fprintf(stream, "[LINK ");
    switch (b->link_node.proto) {
        case ETHERTYPE_IP:
                fprintf(stream, "IP");
                break;
        case ETHERTYPE_REVARP:
                fprintf(stream, "RARP");
                break;
        case ETHERTYPE_ARP:
                fprintf(stream, "ARP");
                break;
        default:
                fprintf(stream, "PROTO %u", b->link_node.proto);
    }
    fprintf(stream, "]");
}

static void print_host_node(FILE *stream, node_t *b)
{
    fprintf(stream, "[HOST addr h%.8X,mask h%.8X,", b->host_node.addr, b->host_node.mask);
    printf_dir(stream, b->host_node.dir);
    fprintf(stream, "]");
}

static void print_proto_node(FILE *stream, node_t *b)
{
    fprintf(stream, "[PROTO ");
    switch(b->proto_node.proto) {
        case IPPROTO_UDP:
            fprintf(stream, "UDP");
            break;
        case IPPROTO_TCP:
            fprintf(stream, "TCP");
            break;
        case IPPROTO_SCTP:
            fprintf(stream, "SCTP");
            break;
        default:
            ERROR("PROTO ERROR");
    }
    fprintf(stream, "]");
}

static void print_port_node(FILE *stream, node_t *b)
{
    fprintf(stream, "[PORT ");
    printf_dir(stream, b->port_node.dir);
    fprintf(stream, " %u]", b->port_node.port);
}

static void print_portrange_node(FILE *stream, node_t *b)
{
    fprintf(stream, "[PORTRANGE %u,%u,", b->portrange_node.port1, b->portrange_node.port2);
    printf_dir(stream, b->portrange_node.dir);
    fprintf(stream, "]");
}


void print_node(FILE *stream, node_t *b)
{
    if (b != NULL)
        switch(b->type) {
            case binary_type:
                print_binary_node(stream, b);
                break;
            case link_type:
                print_link_node(stream, b);
                break;
            case host_type:
                print_host_node(stream, b);
                break;
            case proto_type:
                print_proto_node(stream, b);
                break;
            case port_type:
                print_port_node(stream, b);
                break;
            case portrange_type:
                print_portrange_node(stream, b);
                break;
            default:
                ERROR("NODE ERROR");
        }
    else fprintf(stream, "NULL ");
}

