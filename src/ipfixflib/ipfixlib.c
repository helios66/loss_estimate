#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
//Fri Nov 26 11:04:57 2004
//This file was created automatically by createlib.pl

#include <stdio.h>
#include "mapidflib.h"
#include "debug.h"

    char libname[]="ipfixflib";

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

mapidflib_functionlist_t functions[1];

extern mapidflib_function_def_t * ipfixp_get_funct_info();

mapidflib_functionlist_t* mapidflib_get_function_list()
{
  functions[0].def=ipfixp_get_funct_info();
  functions[0].def->libname=libname;
  functions[0].next=NULL;
  
  return &functions[0];
}

char *mapidflib_get_libname() {
    return libname;
}

__attribute__ ((constructor))
     void init ()
{
    printf("Library ipfixflib loaded\n");
}

__attribute__ ((destructor))
     void fini ()
{
    printf("Library ipfixflib unloaded\n");
}
