#ifndef _MAPILIBHANDLER_H
#define _MAPILIBHANDLER_H 1

#include "mapidflib.h"

extern int mapidflib_get_lib_numfuncts(int libnumber);
mapidflib_functionlist_t* mapidflib_get_lib_functions(int libnumber);
extern mapidflib_function_def_t* mapilh_get_function_def(const char* name, char* devtype);
extern int mapilh_load_library(const char *libpath,const char* library);
extern void mapilh_free_libraries();

#endif
