//Fri Jul 28 14:51:18 2006
//This file was created automatically by createlib.pl

#include <stdio.h>
#include "mapidflib.h"
#include "debug.h"

    char libname[]="stdflib";

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

mapidflib_functionlist_t functions[20];

extern mapidflib_function_def_t * hash_get_funct_info();
extern mapidflib_function_def_t * binop_get_funct_info();
extern mapidflib_function_def_t * bpf_get_funct_info();
extern mapidflib_function_def_t * bucket_get_funct_info();
extern mapidflib_function_def_t * bytec_get_funct_info();
extern mapidflib_function_def_t * dist_get_funct_info();
extern mapidflib_function_def_t * gap_get_funct_info();
extern mapidflib_function_def_t * hashsamp_get_funct_info();
extern mapidflib_function_def_t * pktc_get_funct_info();
extern mapidflib_function_def_t * pktinfo_get_funct_info();
extern mapidflib_function_def_t * res2file_get_funct_info();
extern mapidflib_function_def_t * sample_get_funct_info();
extern mapidflib_function_def_t * startstop_get_funct_info();
extern mapidflib_function_def_t * stats_get_funct_info();
extern mapidflib_function_def_t * strsearch_get_funct_info();
extern mapidflib_function_def_t * sync_get_funct_info();
extern mapidflib_function_def_t * threshold_get_funct_info();
extern mapidflib_function_def_t * to_tcpdump_get_funct_info();
extern mapidflib_function_def_t * toba_get_funct_info();
extern mapidflib_function_def_t * burst_get_funct_info();

mapidflib_functionlist_t* mapidflib_get_function_list()
{
  functions[0].def=hash_get_funct_info();
  functions[0].def->libname=libname;
  functions[0].next=&functions[1];

  functions[1].def=binop_get_funct_info();
  functions[1].def->libname=libname;
  functions[1].next=&functions[2];

  functions[2].def=bpf_get_funct_info();
  functions[2].def->libname=libname;
  functions[2].next=&functions[3];

  functions[3].def=bucket_get_funct_info();
  functions[3].def->libname=libname;
  functions[3].next=&functions[4];

  functions[4].def=burst_get_funct_info();
  functions[4].def->libname=libname;
  functions[4].next=&functions[5];
  
  functions[5].def=bytec_get_funct_info();
  functions[5].def->libname=libname;
  functions[5].next=&functions[6];

  functions[6].def=dist_get_funct_info();
  functions[6].def->libname=libname;
  functions[6].next=&functions[7];

  functions[7].def=gap_get_funct_info();
  functions[7].def->libname=libname;
  functions[7].next=&functions[8];

  functions[8].def=hashsamp_get_funct_info();
  functions[8].def->libname=libname;
  functions[8].next=&functions[9];

  functions[9].def=pktc_get_funct_info();
  functions[9].def->libname=libname;
  functions[9].next=&functions[10];

  functions[10].def=pktinfo_get_funct_info();
  functions[10].def->libname=libname;
  functions[10].next=&functions[11];

  functions[11].def=res2file_get_funct_info();
  functions[11].def->libname=libname;
  functions[11].next=&functions[12];

  functions[12].def=sample_get_funct_info();
  functions[12].def->libname=libname;
  functions[12].next=&functions[13];

  functions[13].def=startstop_get_funct_info();
  functions[13].def->libname=libname;
  functions[13].next=&functions[14];

  functions[14].def=stats_get_funct_info();
  functions[14].def->libname=libname;
  functions[14].next=&functions[15];

  functions[15].def=strsearch_get_funct_info();
  functions[15].def->libname=libname;
  functions[15].next=&functions[16];

  functions[16].def=sync_get_funct_info();
  functions[16].def->libname=libname;
  functions[16].next=&functions[17];

  functions[17].def=threshold_get_funct_info();
  functions[17].def->libname=libname;
  functions[17].next=&functions[18];

  functions[18].def=to_tcpdump_get_funct_info();
  functions[18].def->libname=libname;
  functions[18].next=&functions[19];

  functions[19].def=toba_get_funct_info();
  functions[19].def->libname=libname;
  functions[19].next=NULL;
  
  return &functions[0];
}

char *mapidflib_get_libname() {
    return libname;
}

__attribute__ ((constructor))
     void init ()
{
    printf("Library stdflib loaded\n");
}

__attribute__ ((destructor))
     void fini ()
{
    printf("Library stdflib unloaded\n");
}
