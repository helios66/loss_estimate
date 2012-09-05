#ifndef MAPI_FLOWDRV_H
#define MAPI_FLOWDRV_H 1

#include "mapi.h"
#include "mapi_internal.h"

// Flow driver prototypes

// run when driver loads, _init() name was taken.
void flowdrv_setglobals(const struct flowdrv_globals *globals);
void flowdrv_init();

int flowdrv_connect(flowlist_t *flow_item);
int flowdrv_create_flow(const char *dev);
char * flowdrv_create_offline_device(const char *path, int format);
int flowdrv_start_offline_device(const char *dev);
int flowdrv_delete_offline_device(char *dev);
int flowdrv_close_flow(flowlist_t *flow_item);
int flowdrv_apply_function(flowlist_t *flow_item, const char *funct, va_list vl);
mapi_results_t * flowdrv_read_results(flowlist_t *flow_item, int fid);
struct mapipkt * flowdrv_get_next_pkt(flowlist_t *flow_item, int fid);
int flowdrv_is_connected(flowlist_t *flow_item);
int flowdrv_get_function_info(flowlist_t *flow_item, int fid, mapi_function_info_t *info);
int flowdrv_get_next_function_info(int fd, int fid, mapi_function_info_t *info);
int flowdrv_get_flow_info(flowlist_t *flow_item, mapi_flow_info_t *info);
int flowdrv_get_next_flow_info(int fd, mapi_flow_info_t *info);
int flowdrv_get_next_device_info(int devid, mapi_device_info_t *info);
int flowdrv_get_device_info(int devid, mapi_device_info_t *info);
int flowdrv_stats(const char *dev, struct mapi_stat *stats);
char * flowdrv_get_devtype_of_flow(flowlist_t *flow_item);
#endif
