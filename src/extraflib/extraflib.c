//Mon Nov 27 14:23:17 2006
//This file was created automatically by createlib.pl

#include <stdio.h>
#include "mapidflib.h"
#include "debug.h"

    char libname[]="extraflib";

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

mapidflib_functionlist_t functions[5];

extern mapidflib_function_def_t * anonymizeip_get_funct_info();
extern mapidflib_function_def_t * cooking_get_funct_info();
extern mapidflib_function_def_t * exprflow_get_funct_info();
extern mapidflib_function_def_t * regexp_get_funct_info();
extern mapidflib_function_def_t * topx_get_funct_info();

mapidflib_functionlist_t* mapidflib_get_function_list()
{
  functions[0].def=anonymizeip_get_funct_info();
  functions[0].def->libname=libname;
  functions[0].next=&functions[1];

  functions[1].def=cooking_get_funct_info();
  functions[1].def->libname=libname;
  functions[1].next=&functions[2];

  functions[2].def=exprflow_get_funct_info();
  functions[2].def->libname=libname;
  functions[2].next=&functions[3];

  functions[3].def=regexp_get_funct_info();
  functions[3].def->libname=libname;
  functions[3].next=&functions[4];

  functions[4].def=topx_get_funct_info();
  functions[4].def->libname=libname;
  functions[4].next=NULL;
  
  return &functions[0];
}

char *mapidflib_get_libname() {
    return libname;
}

__attribute__ ((constructor))
     void init ()
{
    printf("Library extraflib loaded\n");
}

__attribute__ ((destructor))
     void fini ()
{
    printf("Library extraflib unloaded\n");
}
