#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/shm.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/sem.h>
#include <fcntl.h>
#include "fhelp.h"
#include "mapid.h"
#include "mapidevices.h"
#include "debug.h"
#include "mapidflib.h"
#include "mapi_errors.h"

#define TIME_M 25769803760ULL
#define TIME_S 4294967296ULL
#define TIME_MS 4294967
#define TIME_US 4294

int fhlp_check_funct(flist_t *flist, const char *fname)
     //return fid of first function with the name fname
{
  flist_node_t *n;
  mapidflib_function_t *funct;
  
  n = flist_head(flist);
  while(n) {
    funct=flist_data(n);
    if(strcmp(funct->instance->def->name,fname)==0)
      return funct->fid;
    n=flist_next(n);
  }
  return 0;
}

int fhlp_check_software_funct(flist_t *flist, mapidflib_function_instance_t *from) 
//Returns 1 if there exists a software function in the function list: flist
{
  flist_node_t *n;
  mapidflib_function_instance_t *funct;
  int check=0;
  
  n = flist_head(flist);
  while(n) {
    funct=flist_data(n);
    if(from==NULL || funct==from)
      check=1;
    if(check) {
      if(strcmp(funct->def->devtype,MAPI_DEVICE_ALL)==0)
	return 1;
    }
    n=flist_next(n);
  }
  return 0;
}

mapidflib_function_instance_t* fhlp_get_function_instance(global_function_list_t *gfl,int fd, int fid)
{
     mapid_flow_info_t *f;	
     mapidflib_function_t *i;

     f=flist_get(gfl->fflist,fd);

	if (!f)
		return(NULL);
     
     i=flist_get(f->flist,fid);


	if(!i)
		return(NULL);
	else
		return(i->instance);
}

mapidflib_function_instance_t* fhlp_get_function_instance_byname(global_function_list_t *gfl, int fd, const char *name)
{
	mapid_flow_info_t *f = NULL;
	mapidflib_function_t *i = NULL;
	flist_node_t *node = NULL;

	while(__sync_lock_test_and_set(&(gfl->lock),1));
	f = flist_get(gfl->fflist,fd);
	if(f)
		node=flist_head(f->flist);
	else
		node=NULL;
	while(node!=NULL) {
		i=node->data;
		if(strcmp(i->instance->def->name, name)==0) {
			gfl->lock = 0;
			return i->instance;
		}
		node=flist_next(node);
	}
	gfl->lock = 0;

	return NULL;
}

int fhlp_create_semaphore(fhlp_sem_t *sem, int num)
//Creates a new semaphore
//Returns 0 if successfull
{
  char pathname[MAPI_STR_LENGTH];
  union semun {
		int val;
		struct semid_ds *buf;
		ushort * array;
	} argument;
  int fd;
  struct group *mapi_group;
  struct semid_ds sem_data;

  argument.val = 0;
  strncpy(pathname,FUNCTION_SEM_TEMPLATE,MAPI_STR_LENGTH);
  if(mkstemp(pathname)==-1)
    return MDLIB_SEM_ERR;

  umask(017);
  if((fd=open(pathname,O_EXCL,FUNCTION_SEM_PERMS))<0)
    return MDLIB_SEM_ERR;
  else
    close(fd);

  strncpy(sem->fname,pathname,MAPI_STR_LENGTH);

  if((sem->key=ftok(pathname,FUNCTION_SEM_PROJECT_ID))<0)
    return MDLIB_SEM_ERR;

  if((sem->id=semget(sem->key,num,FUNCTION_SEM_PERMS | IPC_CREAT)) < 0)
    return MDLIB_SEM_ERR;

  if( semctl(sem->id, 0, SETVAL, argument) < 0) {
    DEBUG_CMD(Debug_Message("ERROR: setting semaphore (%s)", strerror(errno)));
    return MDLIB_SEM_ERR;
  }

  // if a mapi user group exists, set group permissions accordingly,
  // otherwise the group ID will be equal to the user ID of the user that
  // invoked mapid
  mapi_group = getgrnam(MAPI_GROUP_NAME);
  if (mapi_group != NULL) {
    if (semctl(sem->id, 0, IPC_STAT, &sem_data) < 0) {
      DEBUG_CMD(Debug_Message("WARNING: semctl IPC_STAT of %d failed (%s)", sem->id, strerror(errno)));
    }
    sem_data.sem_perm.gid = mapi_group->gr_gid;
    if (semctl(sem->id, 0, IPC_SET, &sem_data) != 0) {
      DEBUG_CMD(Debug_Message("WARNING: semctl IPC_SET of %d failed (%s)", sem->id, strerror(errno)));
    }
  }

  DEBUG_CMD(Debug_Message("Semaphore created. key=%d, id=%d, file=%s", sem->key, sem->id, sem->fname));

  return 0;
}

void fhlp_free_semaphore(fhlp_sem_t *sem)
{
  if (semctl(sem->id,0,IPC_RMID)) {
    DEBUG_CMD(Debug_Message("WARNING: Could not free semaphore id=%d (%s)", sem->id, strerror(errno)));
  }

  if (remove(sem->fname)<0) {
    DEBUG_CMD(Debug_Message("WARNING: Could not remove semaphore file %s (%s)", sem->fname, strerror(errno)));
  }

  DEBUG_CMD(Debug_Message("Removed semaphore id=%d", sem->id));
}


mapidflib_result_t* fhlp_get_res(mapidflib_function_instance_t *instance) 
{
  mapidflib_result_t **res = NULL;

  if(instance->def->get_result==NULL)
    return &instance->result;
  else {
    instance->def->get_result(instance,res);
    return *res;
  }
}

unsigned long long fhlp_str2ull(const char *str)
//Converts a string to an unsigned long long value
{
  float value;
  if(str[0]=='+')
  	str=&str[1];
  sscanf(str,"%f",&value);
  if(strstr(str,"ms")!=NULL)
    return TIME_MS*value;
  else if(strstr(str,"us")!=NULL)
    return TIME_US*value;
  else if(strchr(str,'s')!=NULL)
    return TIME_S*value;
  else if(strchr(str,'m')!=NULL)
    return TIME_M*value;  
  else return value;
  return 0;
}

int fhlp_ull2sec(unsigned long long l, char *str, int length)
//Converts an unsigned unsigned long value to a string representing
//the number of seconds of the value
{
  float sec=(float) l/TIME_S;
  
  return snprintf(str,length,"%f",sec);
}

