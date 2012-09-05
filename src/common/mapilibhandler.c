#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "mapilibhandler.h"
#include "debug.h"
#include "mapi_errors.h"

typedef struct libinfo {
  mapidflib_functionlist_t* functions;
  void* lib;
  struct libinfo* next;
} libinfo_t;

static libinfo_t* libs;

static mapidflib_functionlist_t* (*lib_get_function_list)();

static void addlib(void* libhandle)
{
  libinfo_t* lib=malloc(sizeof(libinfo_t));
  libinfo_t* l;
  char *msg=NULL;

  lib_get_function_list=dlsym(libhandle,"mapidflib_get_function_list");
  lib->functions=lib_get_function_list();
  msg=dlerror();
  if(msg != NULL) {
    perror(msg);
    dlclose(libhandle);
    exit(EXIT_FAILURE);
  }

  lib->lib=libhandle;
  lib->next=NULL;

  if(libs==NULL)
    libs=lib;
  else {
    l=libs;
    while(l->next!=NULL)
      l=l->next;
    l->next=lib;
  }
}

int mapilh_load_library(const char *libpath,const char* library)
{
  void* handle=NULL;
  char buf[2048];
  char path[2048];
  char *lp=path;
  char *p;

  strncpy(path,libpath,2048);

  if(strchr(library,'/')!=NULL) {
    DEBUG_CMD(Debug_Message("WARNING: Invalid library name: %s", library));
    return MAPI_LIBRARY_LOAD_ERR;
  }

  while((p=strchr(lp,':'))!=NULL) {
    *p='\0';
    sprintf(buf,"%s/%s",lp,library);
    DEBUG_CMD(Debug_Message("opening lib: %s", buf));
    handle=dlopen(buf,RTLD_NOW);
    if(handle) {
      addlib(handle);    
      return 0;
    }
    lp=p+1;
  }
  
  sprintf(buf,"%s/%s",lp,library);
  handle=dlopen(buf,RTLD_NOW);
  if(handle) {
    addlib(handle);    
    return 0;
  }
  p = dlerror();
  DEBUG_CMD(Debug_Message("Error loading library: %s", p ? p : "unknown reason"));
  
  return 0;
}

void mapilh_free_libraries()
{
  libinfo_t *cur,*nxt;

  cur=libs;
  while (cur) {
    nxt=cur->next;
//We should not close libraries here.
/*    #ifndef DEBUG_LEAKS
    dlclose(cur->lib);
    #endif
*/
    free(cur);
    cur=nxt;
  }
}

static mapidflib_function_def_t* get_function(char* name, char* devtype, mapidflib_functionlist_t* fl)
{
  while(fl!=NULL) {
    if(strcmp(fl->def->name,name)==0 && strcmp(devtype,fl->def->devtype)==0)
      return fl->def;
    else
      fl=fl->next;
  }

  return NULL;
}

/*
 * The function name can be of the format 
 */
mapidflib_function_def_t* mapilh_get_function_def(const char* name, char* devtype)
{
  mapidflib_function_def_t* f=NULL;
  char* (*lib_get_name)();
  libinfo_t* l;
  char* oid=strdup(devtype);
  int length=strlen(oid);
  char* tmpname=strdup(name);
  char* npos=strchr(tmpname, ':');
  char* foidpos=strchr(tmpname, '!');
  int foidlength=0;
  char *derr;
  
  /*
   * check if we have a library constraint for the function name.
   * the format is '[library:]func_name'
   */
  if (npos) {
    *(npos) = '\0';
    npos++;
  } else {
    npos = tmpname;
  }
  
  /*
   * check if we have a forced OID-constraint.
   * the format is 'func_name[!oid]
   */
  if (foidpos) {
    *(foidpos) = '\0';
    foidpos++;
    foidlength=strlen(foidpos);
    
    if (foidlength<=length) {
      char* tpos = oid+foidlength;
      char tchar = *tpos;
      *tpos = '\0';
      /* in the same tree at all? */
      if (strcmp(oid,foidpos)!=0)
        length=0;
        
      *tpos = tchar;
    }
  }
  
  while(length>0 && f==NULL) {
    /* no match if higher up in the tree */
    if (foidlength>0 && foidlength>length)
      break;
      
    for(l=libs;l!=NULL && f==NULL;l=l->next) {
      lib_get_name=dlsym(l->lib, "mapidflib_get_libname");
      if (lib_get_name) {    
        if (npos!=tmpname && strcmp(lib_get_name(), tmpname)!=0) { 
              /*printf("skipping %s\n", l->functions->def->libname);*/ 
              continue; 
        }
      } else {
        derr=dlerror();
        DEBUG_CMD(Debug_Message("WARNING: Could not lookup function mapidflib_get_libname (%s)", (derr ? derr : "unknown")));
      }
      f=get_function(npos,oid,l->functions);
    }

      
    length-=2;
    if(length>0)
      oid[length]='\0';
  }
  free(tmpname);
  free(oid);
  return f;
}

mapidflib_functionlist_t* mapidflib_get_lib_functions(int libnumber) {
	libinfo_t *l;
	mapidflib_functionlist_t* (*get_function_list)();
	
	for(l=libs;l!=NULL && (libnumber!=0);l = l->next)
		libnumber--;
	if(l==NULL)
	 return NULL;
	
	
	get_function_list=dlsym(l->lib, "mapidflib_get_function_list");
	if(get_function_list)
		return get_function_list();
	else return NULL;	
}

//Returns the number of functions in a library
int mapidflib_get_lib_numfuncts(int libnumber)
{
	int c=0;
	
		mapidflib_functionlist_t *list=mapidflib_get_lib_functions(libnumber);
		while(list->next!=NULL) {
			c++;
			list=list->next;
		}
	  return c;
	
}


char*
mapidflib_get_lib_name(int libnumber)
{
	libinfo_t *l;
	char* (*lib_get_name)();
	
	for(l=libs;l!=NULL && (libnumber!=0);l = l->next)
		libnumber--;
	if(l==NULL)
	 return NULL;
	
	
	lib_get_name=dlsym(l->lib, "mapidflib_get_libname");
	if(lib_get_name)
	  return lib_get_name();
	else
	  return NULL;
	
}

/*mapi_function_def_mini_t*
mapidflib_get_function_info(int libnumber,int functionnumber)
{
	
	libinfo_t *l;
	mapidflib_functionlist_t* f;
	mapi_function_def_mini_t* ret = malloc(sizeof(mapi_function_def_mini_t));
	
	for(l=libs;l!=NULL && (libnumber!=0);l = l->next)
		libnumber--;
	if(l==NULL)
	 return NULL;
	
	
	for(f=l->functions;f!=NULL && (functionnumber!=0);f = f->next)
		functionnumber--;
	if(f)
	  {
	  	strncpy(ret->argdescr,f->def->argdescr,sizeof(ret->argdescr));
	  	strncpy(ret->devtype,f->def->devtype,sizeof(ret->devtype));
	  	strncpy(ret->libname,f->def->libname,sizeof(ret->libname));
	  	strncpy(ret->name,f->def->name,sizeof(ret->name));
	  	strncpy(ret->descr,f->def->descr,sizeof(ret->descr));
	  	return ret;
	  }
	  
	return NULL;
	
}
*/

























