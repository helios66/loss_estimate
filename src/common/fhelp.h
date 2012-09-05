/* 
   MAPI function helper library. Contains various functions for making the
   development of MAPI functions easier
*/

#ifndef _FHELP_H
#define _FHELP_H 1

#include "mapi.h"
#include "mapid.h"
#include "mapiipc.h"
#include "mapidflib.h"
#include "mapidlib.h"

typedef struct fhlp_sem {
  int id;
  key_t key;
  char fname[MAPI_STR_LENGTH];
} fhlp_sem_t;

int fhlp_check_software_funct(flist_t *flist,mapidflib_function_instance_t *from);
int fhlp_check_funct(flist_t *flist, const char *fname);
int fhlp_create_semaphore(fhlp_sem_t *sem,int num);
void fhlp_free_semaphore(fhlp_sem_t *sem);
extern inline mapidflib_result_t* fhlp_get_res(mapidflib_function_instance_t *instance);
mapidflib_function_instance_t* fhlp_get_function_instance(global_function_list_t *glf,int fd, int fid);
mapidflib_function_instance_t* fhlp_get_function_instance_byname(global_function_list_t *gfl, int fd, const char *name);

//Convert a string to an unsigned long long value
unsigned long long fhlp_str2ull(const char *str);
extern inline int fhlp_ull2sec(unsigned long long l,char *str, int length);


#endif
