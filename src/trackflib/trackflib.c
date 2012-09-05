#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
//Thu Nov 10 12:30:25 2005
//This file was created automatically by createlib.pl

#include <stdio.h>
#include "mapidflib.h"
#include "debug.h"

    char libname[]="trackflib";

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

mapidflib_functionlist_t functions[11];

extern mapidflib_function_def_t * trackftp_get_funct_info();
extern mapidflib_function_def_t * gnutella_get_funct_info();
extern mapidflib_function_def_t * torrent_get_funct_info();
extern mapidflib_function_def_t * dc_get_funct_info();
extern mapidflib_function_def_t * edonkey_get_funct_info();
extern mapidflib_function_def_t * ipoverip_get_funct_info();
extern mapidflib_function_def_t * irc_get_funct_info();
extern mapidflib_function_def_t * trackskype_get_funct_info();
extern mapidflib_function_def_t * web_get_funct_info();
extern mapidflib_function_def_t * mapi_get_funct_info();
extern mapidflib_function_def_t * gridftp_get_funct_info();

mapidflib_functionlist_t* mapidflib_get_function_list()
{
  functions[0].def=trackftp_get_funct_info();
  functions[0].def->libname=libname;
  functions[0].next=&functions[1];
 
  functions[1].def=gnutella_get_funct_info();
  functions[1].def->libname=libname;
  functions[1].next=&functions[2];

  functions[2].def=torrent_get_funct_info();
  functions[2].def->libname=libname;
  functions[2].next=&functions[3];

  functions[3].def=dc_get_funct_info();
  functions[3].def->libname=libname;
  functions[3].next=&functions[4];
  
  functions[4].def=edonkey_get_funct_info();
  functions[4].def->libname=libname;
  functions[4].next=&functions[5];

  functions[5].def=ipoverip_get_funct_info();
  functions[5].def->libname=libname;
  functions[5].next=&functions[6];
  
  functions[6].def=irc_get_funct_info();
  functions[6].def->libname=libname;
  functions[6].next=&functions[7];
 
  functions[7].def=trackskype_get_funct_info();
  functions[7].def->libname=libname;
  functions[7].next=&functions[8];

  functions[8].def=web_get_funct_info();
  functions[8].def->libname=libname;
  functions[8].next=&functions[9];
  
  functions[9].def=mapi_get_funct_info();
  functions[9].def->libname=libname;
  functions[9].next=&functions[10];
  
  functions[10].def=gridftp_get_funct_info();
  functions[10].def->libname=libname;
  functions[10].next=NULL;
	
  return &functions[0];
}

char *mapidflib_get_libname() {
    return libname;
}

__attribute__ ((constructor))
     void init ()
{
    printf("Library trackflib loaded\n");
}

__attribute__ ((destructor))
     void fini ()
{
    printf("Library trackflib unloaded\n");
}

