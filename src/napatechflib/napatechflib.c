//Fri Mar  6 19:21:48 2009
//This file was created automatically by createlib.pl

#include <stdio.h>
#include "mapidflib.h"
#include "debug.h"

    char libname[]="napatechflib";

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

mapidflib_functionlist_t functions[2];

extern mapidflib_function_def_t * interface_get_funct_info();
extern mapidflib_function_def_t * bpf_get_funct_info();

mapidflib_functionlist_t* mapidflib_get_function_list()
{
  functions[0].def=interface_get_funct_info();
  functions[0].def->libname=libname;
  functions[0].next=&functions[1];

  functions[1].def=bpf_get_funct_info();
  functions[1].def->libname=libname;
  functions[1].next=NULL;
  
  return &functions[0];
}

char *mapidflib_get_libname() {
    return libname;
}

__attribute__ ((constructor))
     void init ()
{
    printf ("Library napatechflib loaded\n");
}

__attribute__ ((destructor))
     void fini ()
{
    printf ("Library napatechflib unloaded\n");
}

