#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <strings.h>
#include "prefix_preserving_map.h"
#include "debug.h"

int bi_ffs(u_long value);
void hide_addr(unsigned char *raw_addr);
u_long lookup(u_long input, nodehdr_p hdr);

nodehdr_t addr_propagate = { NH_FL_RANDOM_PROPAGATE, 0xffffffff, 0x01000000, 0x00000000, 0x00000000, NULL};

/*
static unsigned rand_accum(unsigned prev, unsigned *px, int ints)
{
    // now, sum it all, shifting all the time
    while (ints--) {
        prev ^= *px++;
        prev = (prev<<1)|(prev>>31);
    }
    return prev;
}
*/

/*
static void rand_start(void)
{
#if     defined(SVR4)
    srand48((long)time(NULL));
#else   // defined(SVR4) 
    srandom((long)time(NULL));
#endif  // defined(SVR4) 
}*/


static long rand32()
{
#if     defined(SVR4)
    return ((lrand48()&0xffff)<<15)|(lrand48()&0xfff);
#else   /* defined(SVR4) */
    return ((random()&0xffff)<<16)|(random()&0xffff);
#endif  /* defined(SVR4) */
}


int bi_ffs(u_long value)
{
    int add = 0;
    static u_char bvals[] = { 0, 4, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1 };

    if ((value&0xFFFF0000) == 0) {
        if (value == 0) {       /* zero input ==> zero output */
            return 0;
        }
        add += 16;
    } else {
        value >>= 16;
    }
    if ((value&0xFF00) == 0) {
        add += 8;
    } else {
        value >>= 8;
    }
    if ((value&0xF0) == 0) {
        add += 4;
    } else {
        value >>= 4;
    }
    return add+bvals[value&0xf];
}

static node_p newnode(void)
{
    node_p node;

    node = (node_p) malloc(sizeof *node);

    if (node == 0) {
        DEBUG_CMD(Debug_Message("malloc failed"));
        exit(2);
    }
    return node;
}


static void freetree(node_p node)
{
    node_p next;

    while (node) {
        next = node->down[0];
        if (node->down[1]){
            freetree(node->down[1]);
        }
        free(node);
        node = next;
    }
}


static inline u_long make_output(u_long value, int flip, nodehdr_p hdr)
{
    if (hdr->flags&NH_FL_RANDOM_PROPAGATE) {
                        /*
                         * the output is:
                         * bits 1-(flip-1):     copied from value
                         * bit  flip:           flip bit (XOR with 1) in value
                         * bits (flip+1)-32:    random
                         */
        if (flip == 32) {
            return value^1;
        } else {                /* get left AND flipped bit */
            return ((((value>>(32-flip))^1)<<(32-flip)) |
                        ((rand32()&0x7fffffff)>>flip)); /* and get right part */
        }
    }

	return 0;
}


static inline node_p make_peer(u_long input, node_p old, nodehdr_p hdr)
{
    node_p down[2];
    int swivel, bitvalue;

    /*
     * become a peer
     * algo: create two nodes, the two peers.  leave orig node as
     * the parent of the two new ones.
     */

    down[0] = newnode();
    down[1] = newnode();

    swivel = bi_ffs(input^old->input);
    bitvalue = EXTRACT_BIT(input, swivel);

    down[bitvalue]->input = input;
    down[bitvalue]->output = make_output(old->output, swivel, hdr);
    down[bitvalue]->down[0] = down[bitvalue]->down[1] = 0;

    *down[1-bitvalue] = *old;       /* copy orig node down one level */

    old->input = down[1]->input;    /* NB: 1s to the right (0s to the left) */
    old->output = down[1]->output;
    old->down[0] = down[0];         /* point to children */
    old->down[1] = down[1];

    return down[bitvalue];
}


void lookup_init(nodehdr_p hdr)
{
    node_p node;
    int opt_class = 32;

    if (hdr->head) {
        freetree(hdr->head);
        hdr->head = 0;
    }

    hdr->head = newnode();
    node = hdr->head;

    /* if this is high order address byte, prime classness if needed */
    if (hdr->addr_mask) {
        /* compute bump as lsb of addr_mask */
        hdr->bump = 1<<(ffs(hdr->addr_mask)-1); /* NOTE -- traditional ffs() */
        if (hdr->flags == NH_FL_COUNTER) {
            node->output = hdr->bump;
        } else {
            /* whatever we do, don't pick up any bits outside of addr_mask */
                /* zeros for high order opt_class bits */
            node->output = rand32()>>opt_class;
                /* no bits outside of addr_mask */
            node->output &= hdr->addr_mask;
        }
        if (opt_class) {
            /* extract bits in addr_mask covered by opt_class */
            hdr->addr_mask = hdr->addr_mask>>(32-opt_class);
            hdr->addr_mask = hdr->addr_mask<<(32-opt_class);
            node->input = hdr->addr_mask;
            node->output |= hdr->addr_mask;
        } else {
            hdr->addr_mask = 0;
            node->input = 0;
        }
    } else {
        node->input = 0;
        /*
         * by using rand32(), we get bit 0 (MSB) randomized;
         * passing 0 wouldn't do at all...
         */
        node->output = rand32();
        hdr->bump = 1;
    }

    node->down[0] = node->down[1] = 0;
}

u_long lookup(u_long input, nodehdr_p hdr)
{
    node_p node;
    int swivel;

    node = hdr->head;   /* non-zero, 'cause lookup_init() already called */
    if (hdr->head == 0) {       /* (but...) */
        DEBUG_CMD(Debug_Message("unexpected zero head"));
    }

    while (node) {
        if (input == node->input) {     /* we found our node! */
            return node->output;
        }
        if (node->down[0] == 0) {       /* need to descend, but can't */
            node = make_peer(input, node, hdr);         /* create a peer */
        } else {
            /* swivel is the first bit the left and right children differ in */
            swivel = bi_ffs(node->down[0]->input^node->down[1]->input);
            if (bi_ffs(input^node->input) < swivel) {/* input differs earlier */
                node = make_peer(input, node, hdr);  /* make a peer */
            } else if (input&(1<<(32-swivel))) {
                node = node->down[1];       /* NB: 1s to the right */
            } else {
                node = node->down[0];       /* NB: 0s to the left */
            }
        }
    }

    /* ??? should not occur! */
    DEBUG_CMD(Debug_Message("unexpected loop termination"));
    exit(1);
}

void hide_addr(unsigned char *raw_addr)
{
    u_long r_addr = ntohl(*((u_long *)raw_addr));
    addr_propagate.cur_input = r_addr;
    r_addr = htonl(lookup(r_addr, &addr_propagate));
    *((u_long *)raw_addr) = r_addr;
}
