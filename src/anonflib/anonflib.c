#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
//Wed Sep 28 15:07:02 2005
//This file was created automatically by createlib.pl

#include <stdio.h>
#include "mapidflib.h"
#include "debug.h"

    char libname[]="anonflib";

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

mapidflib_functionlist_t functions[3];

extern mapidflib_function_def_t * anonprint_get_funct_info();
extern mapidflib_function_def_t * anonymize_get_funct_info();
extern mapidflib_function_def_t * uncook_get_funct_info();

mapidflib_functionlist_t* mapidflib_get_function_list()
{
  functions[0].def=anonprint_get_funct_info();
  functions[0].def->libname=libname;
  functions[0].next=&functions[1];

  functions[1].def=anonymize_get_funct_info();
  functions[1].def->libname=libname;
  functions[1].next=&functions[2];

  functions[2].def=uncook_get_funct_info();
  functions[2].def->libname=libname;
  functions[2].next=NULL;
  
  return &functions[0];
}

char *mapidflib_get_libname() {
    return libname;
}

__attribute__ ((constructor))
     void init ()
{
    printf("Library anonflib loaded\n");
}

__attribute__ ((destructor))
     void fini ()
{
    printf("Library anonflib unloaded\n");
}
