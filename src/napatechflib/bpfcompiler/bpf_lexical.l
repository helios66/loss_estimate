%{
#include <stdlib.h>
#include <ctype.h>

#include "bpf_compile.h"
#include "bpf_node.h"
#include "bpf_pcap.h"

#include "bpf_grammar.h"

void yyerror(char *);

static int stoi(char *);
static inline int xdtoi(int);

#define YY_NO_UNPUT
static YY_BUFFER_STATE in_buffer;

/*
 * TEMPORARILY NOT SUPPORTED
igmp            return IGMP;
igrp            return IGRP;
*/

%}

N               ([0-9]+|(0X|0x)[0-9A-Fa-f]+)
B               ([0-9A-Fa-f][0-9A-Fa-f]?)
W               ([0-9A-Fa-f][0-9A-Fa-f]?[0-9A-Fa-f]?[0-9A-Fa-f]?)

%%
dst             return DST;
src             return SRC;

ether		return LINK;
arp             return ARP;
rarp            return RARP;
ip              return IP;
sctp            return SCTP;
tcp             return TCP;
udp             return UDP;
icmp            return ICMP;

type            return TYPE;
code            return CODE;
flags           return FLAGS;

host            return HOST;
net             return NET;
mask            return NETMASK;
port            return PORT;
portrange       return PORTRANGE;
proto           return PROTO;

and|"&&"        return AND;
or|"||"         return OR;

vlan            return VLAN;
mpls            return MPLS;

multicast       return TK_MULTICAST;
broadcast       return TK_BROADCAST;


[ \r\n\t]       ;
[:/()]                    return yytext[0];
{N}                     { yylval.i = stoi((char *)yytext); return NUM; }
({N}\.{N})|({N}\.{N}\.{N})|({N}\.{N}\.{N}\.{N}) {
                        yylval.s = sdup((char *)yytext); return HID; }
{B}:{B}:{B}:{B}:{B}:{B} { yylval.e = pcap_ether_aton((char *)yytext);
                        return EID; }
icmp-echoreply          { yylval.i = 0; return NUM; }
icmp-unreach            { yylval.i = 3; return NUM; }
icmp-sourcequench       { yylval.i = 4; return NUM; }
icmp-redirect           { yylval.i = 5; return NUM; }
icmp-echo               { yylval.i = 8; return NUM; }
icmp-routeradvert       { yylval.i = 9; return NUM; }
icmp-routersolicit      { yylval.i = 10; return NUM; }
icmp-timxceed           { yylval.i = 11; return NUM; }
icmp-paramprob          { yylval.i = 12; return NUM; }
icmp-tstamp             { yylval.i = 13; return NUM; }
icmp-tstampreply        { yylval.i = 14; return NUM; }
icmp-ireq               { yylval.i = 15; return NUM; }
icmp-ireqreply          { yylval.i = 16; return NUM; }
icmp-maskreq            { yylval.i = 17; return NUM; }
icmp-maskreply          { yylval.i = 18; return NUM; }
tcp-fin                 { yylval.i = 0x01; return NUM; }
tcp-syn                 { yylval.i = 0x02; return NUM; }
tcp-rst                 { yylval.i = 0x04; return NUM; }
tcp-push                { yylval.i = 0x08; return NUM; }
tcp-ack                 { yylval.i = 0x10; return NUM; }
tcp-urg                 { yylval.i = 0x20; return NUM; }
[A-Za-z0-9]([-_.A-Za-z0-9]*[.A-Za-z0-9])? {
                         yylval.s = sdup((char *)yytext); return ID; }
"\\"[^ !()\n\t]+        { yylval.s = sdup((char *)yytext + 1); return ID; }
[^ \[\]\t\n\-_.A-Za-z0-9!<>()&|=]+ {
                        bpf_error("illegal token: %s", yytext); }
.                       { bpf_error("illegal char '%c'", *yytext); }
%%

void lex_init(char *buf)
{
        in_buffer = yy_scan_string(buf);
}

/*
 * Do any cleanup necessary after parsing.
 */
void lex_cleanup()
{
        if (in_buffer != NULL)
                yy_delete_buffer(in_buffer);
        in_buffer = NULL;
}


int yywrap(void) {
    return 1;
}

/* Hex digit to integer. */
static inline int xdtoi(register int c)
{
        if (isdigit(c))
                return c - '0';
        else if (islower(c))
                return c - 'a' + 10;
        else
                return c - 'A' + 10;
}

/*
 * Convert string to integer.  Just like atoi(), but checks for
 * preceding 0x or 0 and uses hex or octal instead of decimal.
 */
static int stoi(char *s)
{
        int base = 10;
        int n = 0;

        if (*s == '0') {
                if (s[1] == 'x' || s[1] == 'X') {
                        s += 2;
                        base = 16;
                }
                else {
                        base = 8;
                        s += 1;
                }
        }
        while (*s)
                n = n * base + xdtoi(*s++);

        return n;
}
