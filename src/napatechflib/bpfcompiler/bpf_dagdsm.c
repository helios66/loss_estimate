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


/*

Structure of Unified_Header
      Basic structure for IPv6                   Differention for IPv4
 1         1                   0           1         1                   0
 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0  Address  5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          L2_REG               |  0x00   |          L2_REG               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          L3_REG               |  0x01   |          L3_REG               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |  0x02   |                               |
|          DST_MAC              |  0x03   |          DST_MAC              |
|                               |  0x04   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |  0x05   |                               |
|          SRC_MAC              |  0x06   |          SRC_MAC              |
|                               |  0x07   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| 802.1p|   802.1q VLAN TAG     |  0x08   | 802.1p|   802.1q VLAN TAG     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       | IF_ID |  0x09   |                       | IF_ID |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |  0x0A   |       SRC_IPv4 addr           |
|                               |  0x0B   |                               |
|                               |  0x0C   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |  0x0D   |                               |
|        SRC_IPv6 addr          |  0x0E   |                               |
|                               |  0x0F   |                               |
|                               |  0x10   |                               |
|                               |  0x11   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |  0x12   |       DST_IPv4 addr           |
|                               |  0x13   |                               |
|                               |  0x14   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |  0x15   |                               |
|        DST_IPv6 addr          |  0x16   |                               |
|                               |  0x17   |                               |
|                               |  0x18   |                               |
|                               |  0x19   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         SRC_PORT              |  0x1A   |        SRC_PORT               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         DST_PORT              |  0x1B   |        DST_PORT               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |  0x1C   |                               |
|                               |  0x1D   |                               |
|                               |  0x1E   |                               |
|        INTER_ADDR             |  0x1F   |                               |
|                               |  0x20   |                               |
|                               |  0x21   |                               |
|                               |  0x22   |                               |
|                               |  0x23   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           PLEN                |  0x24   |           PLEN                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |   PROTOCOL    |  0x25   |               |   PROTOCOL    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        DRAM_ADDR              |  0x3F   |        DRAM_ADDR              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <setjmp.h>
#include <string.h>

#include "utils.h"
#include "bpfcompiler.h"
#include "bpf_dagdsm.h"
#include "bpf_node.h"
#include "bpf_compile.h"
#include "bpf_pcap.h"

/* extern declarations */
extern jmp_buf bpf_error_jmp;
extern int bpf_error_set;
extern char *bpf_errbuf;

/* prototypes */
// TODO: rename all to ntpl
static void dagdsm_compile_binary_node(dstring_t *s, node_t *b);
static void ntpl_compile_proto_node(dstring_t *s, node_t *b);
static void dagdsm_compile_host_node(dstring_t *s, node_t *b);
static void dagdsm_compile_port_node(dstring_t *s, node_t *b);

void dagdsm_compile_node(dstring_t *s, node_t *b);

static void dagdsm_compile_binary_node(dstring_t *s, node_t *b)
{
    // XXX: Do we need ( and ) around expr??
    if (b->binary_node.left != NULL && b->binary_node.right != NULL)
        dsprintf(s, "(");

    dagdsm_compile_node(s, b->binary_node.left);

    if (b->binary_node.left != NULL && b->binary_node.right != NULL) {
        if (b->binary_node.type == Q_AND) {
            dsprintf(s, " AND ");
        }
        else if (b->binary_node.type == Q_OR) {
            dsprintf(s, " OR ");
        }
    }

    dagdsm_compile_node(s, b->binary_node.right);

    if (b->binary_node.left != NULL && b->binary_node.right != NULL)
        dsprintf(s, ")");
}

void dsprinf_ipv4(dstring_t *s, u_int32_t addr)
{
    dsprintf(s, "[%d.%d.%d.%d]",
        (addr >> 24) & 0xFF,
        (addr >> 16) & 0xFF,
        (addr >> 8) & 0xFF,
        addr & 0xFF);
}

static void dagdsm_compile_proto_node(dstring_t *s, node_t *b)
{
    switch(b->proto_node.proto) {
        case IPPROTO_UDP:
            dsprintf(s, "Layer4Protocol == UDP");
            break;
        case IPPROTO_TCP:
            dsprintf(s, "Layer4Protocol == TCP");
            break;
        case IPPROTO_ICMP:
            dsprintf(s, "Layer4Protocol == ICMP");
            break;
        // TODO: 'Other' protocol for != UDP,TCP,ICMP
        // TODO: Can implement custom protocols using Data offsets ref NTPL spec example.
        default:
            ERROR("Only TCP, UDP and ICMP protocols currently implemented...");
    }
}

static void dagdsm_compile_host_node(dstring_t *s, node_t *b)
{
    // TODO: MASK ?
/*            dsprinf_ipv4(s, b->host_node.mask); */
    switch(b->host_node.dir) {
        case Q_SRC:
            dsprintf(s, "Data[DynOffset=DynOffIPv4Frame; Offset=12; DataType=[IPv4Addr] ==  ");
            dsprinf_ipv4(s, b->host_node.addr);
            break;
        case Q_DST:
            dsprintf(s, "Data[DynOffset=DynOffIPv4Frame; Offset=16; DataType=[IPv4Addr] ==  ");
            dsprinf_ipv4(s, b->host_node.addr);
            break;
        default:
            CERROR();
    }
}

void dsprintf_mac(dstring_t *s, unsigned char *eaddr)
{
    dsprintf(s, "[%02X:%02X:%02X:%02X:%02X:%02X]",
            eaddr[0],eaddr[1],eaddr[2],
            eaddr[3],eaddr[4],eaddr[5]);
}

static void dagdsm_compile_ehost_node(dstring_t *s, node_t *b)
{
    // TODO: MASK?
    /*             dsprintf_mac(s, b->ehost_node.mask); */
    switch(b->ehost_node.dir) {
        case Q_SRC:
            dsprintf(s, "Data[Offset=6; DataType=MacAddr] == ");
            dsprintf_mac(s, b->ehost_node.eaddr);
            break;
        case Q_DST:
            dsprintf(s, "Data[Offset=0; DataType=MacAddr] == ");
            dsprintf_mac(s, b->ehost_node.eaddr);
            break;
        default:
            CERROR();
    }
}

static void dagdsm_compile_port_node(dstring_t *s, node_t *b)
{
    switch(b->port_node.dir) {
        case Q_SRC:
            dsprintf(s, "Data[DynOffset=DynOffIPv4Data; Offset=0; DataType=[15:0]] == %d",
                     b->port_node.port);
            break;
        case Q_DST:
            dsprintf(s, "Data[DynOffset=DynOffIPv4Data; Offset=2; DataType=[15:0]] == %d",
                     b->port_node.port);
            break;
        default:
            CERROR();
    }
}

static void dagdsm_compile_type_node(dstring_t *s, node_t *b)
{
    switch(b->type_node.type) {
        case Q_TYPE:
            dsprintf(s, "Data[DynOffset=DynOffIcmpFrame; Offset=0; DataType=[7:0]] == %d",
                     b->type_now.value);
            break;

        case Q_CODE:
            dsprintf(s, "Data[DynOffset=DynOffIcmpFrame; Offset=1; DataType=[7:0]] == %d",
                     b->type_now.value);
            break;

        case Q_FLAGS:
/*            dsprintf(s, "                    <tcp-flags>\n"
                        "                        <flags>%d</flags>\n"
                        "                        <mask hex=\"true\">3F</mask>\n"
                        "                    </tcp-flags>\n", b->type_node.value);
  */          // TODO
            ERROR("TCP flags filtering not done..");
            break;

        default:
            CERROR();
    }
}

/*
 * Compile BPF nodes into DAGDSM filter loader string
 */
void dagdsm_compile_node(dstring_t *s, node_t *b)
{
    // TODO: NOT node?? maybe pass it as an arg to the compile_*_node funcs and let that determine == or !=
    if (b != NULL) {
        switch(b->type) {
            case binary_type:
                dagdsm_compile_binary_node(s, b);
                break;
            case link_type:
                // TODO: export to own func and switch. to explicitly specify IP type
                if ((b->link_node.proto != ETHERTYPE_IP) && (b->link_node.proto != ETHERTYPE_8021Q) &&
                        (b->link_node.proto != ETHERTYPE_MPLS)) {
                    ERROR("Only VLAN(802.1Q)/MPLS/Ethernet + IPv4 frames supported currently for DAG DSM.");
                }
                if (b->link_node.proto == ETHERTYPE_8021Q) { //VLAN
                    /*if (strcmp(frametype, "ethernet-mpls") == 0) {
                        fprintf(stderr, "Error: Tried to apply VLAN when MPLS is already applied.\n");
                        free(frametype);
                        CERROR();
                    }
                    strcpy(frametype, "ethernet-vlan");*/
                    dsprintf(s, "Encapsulation == VLAN");
                } else if (b->link_node.proto == ETHERTYPE_MPLS) {
                    /*if (strcmp(frametype, "ethernet-vlan") == 0) {
                        fprintf(stderr, "Error: Tried to apply MPLS when VLAN is already applied.\n");
                        free(frametype);
                        CERROR();
                    }
                    strcpy(frametype, "ethernet-mpls");*/
                    dsprintf(s, "Encapsulation == MPLS");
                }
                break;
            case ehost_type:
                dagdsm_compile_ehost_node(s, b);
                break;
            case mpls_type:
                // TODO
                ERROR("not done...");
                /*if (layer == LAYER_LINK) {
                    dsprintf(s, "            <mpls-label>\n"
                                "                <label>%lu</label>\n"
                                "                <mask>%lu</mask>\n"
                                "            </mpls-label>\n",
                                (long unsigned int)b->mpls_node.label,
                                (long unsigned int)b->mpls_node.mask);
                }*/
                break;
            case vlan_type:
                /*
                if (layer == LAYER_LINK) {
                    dsprintf(s, "            <vlan-id>\n"
                                "                <id>%lu</id>\n"
                                "                <mask>%lu</mask>\n"
                                "            </vlan-id>\n",
                                (long unsigned int)b->vlan_node.id,
                                (long unsigned int)b->vlan_node.mask);
                }*/
                // TODO: Implement Mask? maybe with reduced datatype or diff offset?
                // TODO: join with link_type ??
                dsprintf(s, "Data[DynOffset=DynOffLayer2Frame; Offset=14; DataType=[15:0]] == %lu", (long unsigned int)b->vlan_node.id);
                break;
            case host_type:
                dagdsm_compile_host_node(s, b);
                break;
            case proto_type:
                ntpl_compile_proto_node(s, b);
                break;
            case port_type:
                dagdsm_compile_port_node(s, b);
                break;
            case portrange_type:
                ERROR("PORTRANGE not supported for DAG platform.");
                break;
            case type_type:
                dagdsm_compile_type_node(s, b);
                break;
            case ethertype_type:
                dsprintf(s, "Data[DynOffset=DynOffEtherType; Offset=0; DataType=[15:0]] == %d",
                         (b->ethertype_node.type & 0xFFFF));
                break;
            default:
                CERROR();
        }
    } else CERROR();
}

static char **transform_and_compile(node_t *b, int *count)
{
    dstring_t s,f;
    node_t **list;
    char **rules;
    int i;

    dsnew(&s);
//    dsnew(&f);

    list = transform_tree(b, count);
    if (list == NULL) return NULL;

    rules = xmalloc(sizeof(char *) * *count);

    BPF_DEBUG_CMD(
        fprintf(stderr, "resulting rules:\n");
        for (i=0; i < *count; i++) {
            fprintf(stderr, "%u: ", i+1);
            print_node(stderr, list[i]);
            fprintf(stderr, "\n");
        }
    )

    for (i=0; i < *count; i++) {
        dsclear(&s);
//        dsclear(&f);

        dagdsm_compile_node(&s, list[i]);
/*
        dsprintf(&f, "        <%s>\n%s"
                     "            <ipv4>\n%s"
                     "            </ipv4>\n"
                     "        </%s>\n",
                     frametype, dsgets(&l), dsgets(&s), frametype);
                     */
        // TODO
        rules[i] = dsstrdup(&s); //f);
    }

    dsfree(&s);
//    dsfree(&f);

    /* Free list of root's nodes*/
    free(list);

    return rules;
}

/*****************************************************************************/

/*
 * Compile bpf filter for DAG adapter with DSM classification
 */
dagdsm_bpf_filter_t *dagdsm_bpf_compile(dagdsm_bpf_filter_t *bpf_filter, char *buf, int index, char *errbuf)
{
    node_t *root;
    dagdsm_filter_t *filter;
    dagdsm_filter_t **filters;
    char **rules;
    int nrules;
    int filter_cnt;

    if (buf == NULL) {
        strcpy(errbuf, "dagdsm_bpf_compile: BPF expression is NULL.\n");
        return NULL;
    }

    BPF_DEBUG_CMD(fprintf(stderr, "*** dagdsm_bpf_compile expression #%d: %s\n", index, buf));

    /* Compile BPF filter */
    if (bpf_compile(&root, errbuf, buf, 0) < 0) {
        return NULL;
    }

    /* Error setup */
    bpf_errbuf = errbuf;
    bpf_error_set = 1;
    if (setjmp(bpf_error_jmp)) {
        bpf_error_set = 0;
        //TODO: free memory
        //free_nodes();
        return NULL;
    }

    BPF_DEBUG_CMD(fprintf(stderr, "compiled node: "));
    BPF_DEBUG_CMD(print_node(stderr, root));
    BPF_DEBUG_CMD(fprintf(stderr, "\n"));

    /* Transform and compile filter in  */
    rules = transform_and_compile(root, &nrules);
    if (rules == NULL) return NULL;

    bpf_error_set = 0;
    /* Delete all nodes */
    free_nodes();

    /* Create dagdsm_filter */
    filter = xmalloc(sizeof(dagdsm_filter_t));
    filter->nrules = nrules;
    filter->rules = rules;
    filter->bpf = strdup(buf);
    filter->index = index;

    /* Create bpf_filter */
    if (bpf_filter == NULL) {
        bpf_filter = xmalloc(sizeof(dagdsm_bpf_filter_t));
        filters = xmalloc(sizeof(dagdsm_filter_t *));
        filter_cnt = 1;
    } else {
        filters = bpf_filter->filters;
        filter_cnt = bpf_filter->nfilters + 1;
        filters = xrealloc(filters, filter_cnt * sizeof(dagdsm_filter_t *));
    }
    bpf_filter->nfilters = filter_cnt;
    bpf_filter->filters = filters;
    bpf_filter->filters[filter_cnt-1] = filter;

    BPF_DEBUG_CMD(fprintf(stderr, "compiling finished\n"));

    return bpf_filter;
}

/*
 * Write filter to buffer, the buffer must be freed afterwards!
 */
char *dagdsm_bpf_xprintf(dagdsm_bpf_filter_t *bpf_filter, char *errbuf)
{
    dstring_t s;
    char *retval;
    int f, ff, r, first_cnt, cnt = 0;

    if (bpf_filter == NULL) {
    	strcpy(errbuf, "dagdsm_bpf_xprintf: NULL argument.");
        return NULL;
    }

    /* Create variable size string and print header */
    dsnew(&s);
    dsprintf(&s, "Capture = ");


    // TODO FIXME: there are no OR nodes? as OR turns into two filters with only AND in them
    //          is this easy to alter

    /* Print filter rules */
    for (f=0; f < bpf_filter->nfilters; f++) {
        //first_cnt = cnt;
        for (r=0; r < bpf_filter->filters[f]->nrules; r++) {
            /*dsprintf(&s, "    <filter>\n"
                         "        <name>filter%d</name>\n"
                         "        <number>%d</number>\n%s"
                         "    </filter>\n",
                         cnt, cnt, bpf_filter->filters[f]->rules[r]);

            cnt++;*/
            dsprintf(s, "%s ", bpf_filter->filters[f]->rules[r]));
        }
        /*dsprintf(&s, "    <!-- $DAG-DSM-TAG$ bpf-index:%d\tfilters-used:",
                bpf_filter->filters[f]->index);

        for (ff=0; ff<first_cnt; ff++)
            dsprintf(&s, "0");
        for (ff=0; ff<r; ff++)
            dsprintf(&s, "1");
        for (ff=first_cnt+r; ff % 8; ff++)  // align to the byte width
            dsprintf(&s, "0");

        dsprintf(&s, "\t\n         bpf-expression:%s\n    -->\n\n", bpf_filter->filters[f]->bpf);*/
    }

    retval = dsstrdup(&s);
    dsfree(&s);

    return retval;
}
/*
 * Gets the binary mask for the filter added as the last. Bit 0 (LSB) conforms
 * to hardware filter 0, bit 1 to filter 1 etc.
 */  
unsigned int dagdsm_bpf_get_last_usage_mask(dagdsm_bpf_filter_t *bpf_filter)
{
    unsigned int mask = 0, f, i = 0, nf, nr;

    if (bpf_filter != NULL) {
        nf = bpf_filter->nfilters;
        if (nf > 0) {

            for (f=0; f < nf-1; f++)
                i += bpf_filter->filters[f]->nrules;

            nr = bpf_filter->filters[nf-1]->nrules;
            if ((i+nr) <= 8*sizeof(int)) {
                for (; nr ; nr--)
                    mask |= (1 << (i+nr-1));
            } else {
                BPF_DEBUG_CMD(fprintf(stderr, "dagdsm_bpf_get_last_usage_mask: Too many filters for the width of int type!\n"));
            } 
        }
    } else {
        BPF_DEBUG_CMD(fprintf(stderr, "dagdsm_bpf_get_last_usage_mask: NULL argument.\n"));
    }

    return mask;
}

/*
 * Returns the number of hardware filters that shall be used
 * for entire configuration.
 */
int dagdsm_bpf_get_filter_count(dagdsm_bpf_filter_t *bpf_filter)
{
    int cnt = 0, f;

    if (bpf_filter != NULL) {
        for (f=0; f < bpf_filter->nfilters; f++) {
            cnt += bpf_filter->filters[f]->nrules;
        }
    }

    return cnt;
}

/*
 * Free resources allocated by the filter
 */
void dagdsm_bpf_free(dagdsm_bpf_filter_t *bpf_filter)
{
    int f,r;

    if (bpf_filter != NULL) {
        /* Free resources */
        for (f=0; f < bpf_filter->nfilters; f++) {
            for (r=0; r < bpf_filter->filters[f]->nrules; r++) {
                /* Free single rules */
                free(bpf_filter->filters[f]->rules[r]);
            }
            /* Free the table of rules */
            free(bpf_filter->filters[f]->rules);
            /* Free BPF expression */
            free(bpf_filter->filters[f]->bpf);
            /* Free single (sub)filters */
            free(bpf_filter->filters[f]);
        }
        /* Free the table of filters */
        free(bpf_filter->filters);
        /* Free the bpf_filter */
        free(bpf_filter);
    }
}
