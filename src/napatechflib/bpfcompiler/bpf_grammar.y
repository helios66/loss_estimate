%{
#include <stdio.h>
#include <stdlib.h>

#include "bpf_compile.h"
#include "bpf_node.h"
#include "bpf_pcap.h"

#define QSET(q, p, d, a) (q).proto = (p),\
                         (q).dir = (d),\
                         (q).addr = (a)

/* prototypes */
int yylex(void);

int n_errors = 0;

static struct qual qerr = { Q_UNDEF, Q_UNDEF, Q_UNDEF, Q_UNDEF };

static void yyerror(char *msg)
{
    ++n_errors;
    bpf_error("%s", msg);
}

int yyparse();

int bpf_parse()
{
    return (yyparse());
}

%}

%union {
    int i;
    char *s;
    unsigned char *e;
    struct {
        struct qual q;
        node_t *b;
    } blk;
    struct block *rblk;
}

%type   <blk>   expr id nid pid qid term
%type   <blk>   head
%type   <i>     pqual dqual aqual tqual
%type   <i>     pname pnum
%type   <blk>   and or paren null prog
%type   <rblk>  other

%token  DST SRC HOST
%token  NET NETMASK PORT PORTRANGE PROTO
%token  ARP RARP IP SCTP TCP UDP ICMP IGMP IGRP
%token  TK_BROADCAST TK_MULTICAST
%token  NUM CODE TYPE FLAGS
%token  LINK
%token  ID EID HID
%token  VLAN MPLS


%type   <s> ID
%type   <e> EID
%type   <s> HID
%type   <i> NUM

%left OR AND
%left '|'
%left '&'

%%
prog:     null expr             { finish_parse($2.b); }
        | null
        ;

null:    /* null */             { $$.q = qerr; }
        ;

expr:     term
        | expr and term         { $$.b = new_and_node($1.b, $3.b);
                                    $$.q = $3.q; }
        | expr and id           { $$.b = new_and_node($1.b, $3.b);
                                    $$.q = $3.q; }
        | expr or term          { $$.b = new_or_node($1.b, $3.b);
                                    $$.q = $3.q; }
        | expr or id            { $$.b = new_or_node($1.b, $3.b);
                                    $$.q = $3.q; }
        ;

and:      AND                   { $$ = $<blk>0; }
        ;

or:       OR                    { $$ = $<blk>0; }
        ;

term:     head id               { $$ = $2; }
        | paren expr ')'        { $$.b = $2.b; $$.q = $1.q; }
        | pname                 { $$.b = gen_proto_abbrev($1); $$.q = qerr; }
        | other                 { $$.b = $1; $$.q = qerr; }
        ;

paren:   '('                    { $$ = $<blk>0; }
        ;

id:       nid
        | pnum                  { $$.b = gen_ncode(NULL, $1, $$.q = $<blk>0.q); }
        | paren pid ')'         { $$ = $2; }
        ;

nid:     ID                     { $$.b = gen_scode($1, $$.q = $<blk>0.q); }
        | HID '/' NUM           { $$.b = gen_mcode($1, NULL, $3,
                                    $$.q = $<blk>0.q); }
        | HID NETMASK HID       { $$.b = gen_mcode($1, $3, 0,
                                    $$.q = $<blk>0.q); }
        | HID                   {
                                  $$.q = $<blk>0.q;
                                  $$.b = gen_ncode($1, 0, $$.q);
                                }
        | EID                   { 
                                  $$.b = gen_ecode($1, $$.q = $<blk>0.q);
                                  free($1);
                                }
        ;

pid:      nid
        | qid and id            { $$.b = new_and_node($1.b, $3.b);
                                    $$.q = $3.q; }
        | qid or id             { $$.b = new_or_node($1.b, $3.b);
                                    $$.q = $3.q; }
        ;

qid:     pnum                   { $$.b = gen_ncode(NULL, $1,
                                    $$.q = $<blk>0.q); }
        | pid
        ;

pnum:     NUM                   { $$ = $1; }
        | paren pnum ')'        { $$ = $2; }
        ;

head:     pqual dqual aqual     { QSET($$.q, $1, $2, $3); }
        | pqual dqual           { QSET($$.q, $1, $2, Q_DEFAULT); }
        | pqual aqual           { QSET($$.q, $1, Q_DEFAULT, $2); }
        | pqual PROTO           { QSET($$.q, $1, Q_DEFAULT, Q_PROTO); }
        ;

/* protocol level qualifiers */
pqual:    pname
        |                       { $$ = Q_DEFAULT; }
        ;

/* 'direction' qualifiers */
dqual:    SRC                   { $$ = Q_SRC; }
        | DST                   { $$ = Q_DST; }
        | SRC OR DST            { $$ = Q_OR; }
        | DST OR SRC            { $$ = Q_OR; }
        | SRC AND DST           { $$ = Q_AND; }
        | DST AND SRC           { $$ = Q_AND; }
        ;

/* address type qualifiers */
aqual:    HOST                  { $$ = Q_HOST; }
        | NET                   { $$ = Q_NET; }
        | PORT                  { $$ = Q_PORT; }
        | PORTRANGE             { $$ = Q_PORTRANGE; }
        ;

/* type/code/flag qualifiers */
tqual:    CODE                  { $$ = Q_CODE; }
        | TYPE                  { $$ = Q_TYPE; }
        | FLAGS                 { $$ = Q_FLAGS; }
        ;

pname:    LINK                  { $$ = Q_LINK; }
        | IP                    { $$ = Q_IP; }
        | ARP                   { $$ = Q_ARP; }
        | RARP                  { $$ = Q_RARP; }
        | SCTP                  { $$ = Q_SCTP; }
        | TCP                   { $$ = Q_TCP; }
        | UDP                   { $$ = Q_UDP; }
        | ICMP                  { $$ = Q_ICMP; }
        | IGMP                  { $$ = Q_IGMP; }
        | IGRP                  { $$ = Q_IGRP; }
        ;

other:    pqual TK_BROADCAST    { $$ = gen_broadcast($1); }
        | pqual TK_MULTICAST    { $$ = gen_multicast($1); }
        | VLAN pnum             { $$ = gen_vlan($2); }
        | VLAN                  { $$ = gen_vlan(-1); }
        | MPLS pnum             { $$ = gen_mpls($2); }
        | MPLS                  { $$ = gen_mpls(-1); }
        | pqual tqual pnum      { $$ = gen_type($1, $2, $3); }
        | pqual tqual           { $$ = gen_type($1, $2, -1); }
        ;

/*
 * ----------------------------------------------------------------------------
 */
%%
