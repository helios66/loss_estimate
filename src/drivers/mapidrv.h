#ifndef _MAPIDRV_H
#define _MAPIDRV_H 1

#include "mapi.h"
#include "mapid.h"
#include "mapidlib.h"

/*
 * Creates a new mapi flow
 * Differs from the one in mapi.h in that it also takes
 * the flow descriptor as parameter.
 * The value of the flow descriptor is assigned in mapid.c
 */
int mapidrv_create_flow(int devid,int fd,char **devtype);
int mapidrv_close_flow(int devid,int fd);
/* for mapidlib errorcode */
int  mapidrv_get_errno(int devid,int fd);

/* These functions are similar to the ones in mapi.h */
int mapidrv_apply_function(int devid,int fd, int flags, char* function, mapiFunctArg *fargs);
int mapidrv_read_results(int devid,int fd,int fid,mapid_result_t** result);
int mapidrv_connect(int devid,int fd);
mapid_funct_info_t* mapidrv_get_flow_functions(int devid,int fd); //Deprecated and should be removed
int mapidrv_get_flow_info(int devid,int fd,mapi_flow_info_t *info);
int mapidrv_load_library(int devid,char* lib);
int mapidrv_add_device(const char *devname,int file, int devid, global_function_list_t *gflist, void *param);
int mapidrv_delete_device(int devid);
int mapidrv_start_offline_device( int devid);
int mapidrv_stats(int devid, char **devtype, struct mapi_stat *stats);

#endif







