#ifndef _MAPIIPC_H
#define _MAPIIPC_H 1

#include "mapi.h"

#define MAX_SEND_SIZE 8192//1024
#define FUNCTARGS_BUF_SIZE 7168
#define DATA_SIZE 7168
#define DIMAPI_DATA_SIZE 2000000
#define FUNCT_NAME_LENGTH 256
#define ARG_LENGTH 32
#define MAPIDSOCKHOME "%s/.mapid.sock"
#define MAPIDSOCKGLOBAL "/tmp/mapid.sock"
#define MAPIDGSOCKHOME "%s/.mapid%d.sock"
#define MAPIDGSOCKGLOBAL "/tmp/mapid%d.sock"

//All IPC code needs to be rewritten and cleand up.
//To support dynamic loading of new functions we should have an IPC
//system that do not need to be changed for each new function type 
//that is added.

//Messages types that can be sent to/from mapi and mapid
typedef enum {
  CREATE_FLOW,
  CREATE_FLOW_ACK,
  APPLY_FUNCTION,
  APPLY_FUNCTION_ACK,
  READ_RESULT,
  READ_RESULT_ACK,
  CONNECT,
  CONNECT_ACK,
  CLOSE_FLOW,
  CLOSE_FLOW_ACK,
  READ_ERROR,
  READ_ERROR_ACK,
  ERROR_ACK,
  CREATE_OFFLINE_DEVICE,
  CREATE_OFFLINE_DEVICE_ACK,
  START_OFFLINE_DEVICE,
  START_OFFLINE_DEVICE_ACK,
  DELETE_OFFLINE_DEVICE,
  DELETE_OFFLINE_DEVICE_ACK,
  CREATE_OFFLINE_FLOW,
  CREATE_OFFLINE_FLOW_ACK,
  SET_AUTHDATA,
  SET_AUTHDATA_ACK,
  AUTHENTICATE,
  AUTHENTICATE_ACK,
  LOAD_LIBRARY,
  LOAD_LIBRARY_ACK,
  GET_DEVICE_INFO,
  GET_DEVICE_INFO_ACK,
  GET_NEXT_DEVICE_INFO,
  GET_DEVICE_INFO_NACK,
  GET_LIBRARY_INFO,
  GET_LIBRARY_INFO_ACK,
  GET_NEXT_LIBRARY_INFO,
  GET_LIBRARY_INFO_NACK,
  GET_FLOW_INFO,
  GET_FLOW_INFO_ACK,
  GET_NEXT_FLOW_INFO,
  GET_FLOW_INFO_NACK,
  GET_FUNCTION_INFO,
  GET_FUNCTION_INFO_ACK,
  GET_NEXT_FUNCTION_INFO,
  GET_FUNCTION_INFO_NACK,
  GET_LIBPATH,
  GET_LIBPATH_ACK,
  GET_LIBPATH_NACK,
  GET_LIBS,
  GET_LIBS_ACK,
  GET_LIBS_NACK,
  SEND_FD,
  GET_NEXT_PKT,
  GET_NEXT_PKT_ACK,
  IGNORE_SLEEP, // reconnection ...
  IGNORE_NOTIFY,
  MAPI_STATS,
  MAPI_STATS_ACK,
  MAPI_STATS_ERR
} mapiipcMsg;

#define INT 1
#define STRING 2
#define UNSIGNED_LONG_LONG 3

extern void addarg(mapiFunctArg **pos, void *arg, int type);
extern int getargint(mapiFunctArg **pos);
extern char getargchar(mapiFunctArg **pos);
extern char * getargstr(mapiFunctArg **pos);
extern unsigned long long getargulonglong(mapiFunctArg **pos);

#endif//_MAPIIPC_H
