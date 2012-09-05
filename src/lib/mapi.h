#ifndef _MAPI_H
#define _MAPI_H 1

#include <sys/ipc.h>
#include <time.h>
#include <syslog.h>
#define PAPI 10

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

typedef int boolean_t;

#define MAPI_STR_LENGTH 256
#define MAPI_ERRORSTR_LENGTH 512

typedef unsigned char mapiFunctArg;

#define INT 1
#define STRING 2
#define UNSIGNED_LONG_LONG 3
#define CHAR 4

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define MAPI_UNUSED                           \
  __attribute__((__unused__))
#else
#define MAPI_UNUSED
#endif

enum mapi_file_formats {
  MFF_PCAP,
  MFF_RAW,
  MFF_DAG_ERF,
  MFF_COMBO6,
  MFF_NAPATECH
};
#define MFF_PCAP_STR "MFF_PCAP"
#define MFF_DAG_ERF_STR "MFF_DAG_ERF"
#define MFF_NAPATECH_STR "MFF_NAPATECH"

#define DEFAULT_DIMAPI_PORT 2233

enum mapi_read_result_method {
  MAPI_COPY, //Copy result
  MAPI_REF //Return pointer to result
};

enum cooking_direction {
  CLIENT_SIDE = 1, //client's only data
  SERVER_SIDE, //server's only data
  BOTH_SIDE //all data
};

enum toba_flg {
  WAIT = 0,
  NOWAIT
};

typedef enum mapi_offline_device_status {
  DEVICE_ONLINE,
  DEVICE_SETUP,
  DEVICE_READING,
  DEVICE_FINISHED, //Copy result
  DEVICE_DELETED //Return pointer to result
} mapi_offline_device_status_t;

enum mapi_flow_status {
  FLOW_INIT, //Flow is being initialized
  FLOW_ACTIVE, //Flow is active and analyzing packets
  FLOW_FINISHED, //Offline flow is finished analyzing file
  FLOW_CLOSED //Flow is closed
};

typedef struct mapi_flow_info {
  uid_t uid; //UID of user running the flow
  int fd; //Flow descriptor
  int devid; // ID of the device used by the flow
  char device[MAPI_STR_LENGTH]; //Name of device used by the flow
  unsigned num_functions; //Number of functions applied to the flow
  time_t start; //Start of flow
  time_t end; //End of flow
  enum mapi_flow_status status; //Status of flow
#ifdef WITH_PRIORITIES
  int priority;
#endif
} mapi_flow_info_t;

/* It should NOT be confused with mapi_results_t struct that is returned by mapi_read_results.
   It is only for internal use, it may have to be renamed in internal_result_t */
typedef struct mapi_result {
  void *res; //Pointer to function specific result data
  unsigned size; //size of result
} mapi_result_t;

typedef struct mapi_function_info {
  int fid; //Function ID
  char name[MAPI_STR_LENGTH]; //Name of function
  char libname[MAPI_STR_LENGTH]; //Name of library that the function is part of
  char devtype[MAPI_STR_LENGTH]; //Device type the function is compatible with
  unsigned long long pkts; //Number of packets that has been processed
  unsigned long long passed_pkts; //Number of packets that has passed the function
  int result_size; //Size of the function's result
} mapi_function_info_t;

/*Structure that contains device independant information about packets*/
struct mapipkt {
  unsigned long long ts; /* NTP 64-bit timestamp of packet as defined in RFC 1305 */
  unsigned short ifindex; //Interface index
  unsigned caplen; /* Number of bytes from the packet that were captured*/
  unsigned wlen; /* Wire length. Real lenght of packet as seen on network*/
  unsigned char pkt; /* Pointer to the IP packet */
};

/*structure returned by mapi_read_results*/
typedef struct mapi_results {
  void *res; //Pointer to function specific result data
  unsigned long long ts; //timestamp
  int size; //size of the result
} mapi_results_t;

typedef struct mapi_device_info {
  int id;
  char device[MAPI_STR_LENGTH];
  char name[MAPI_STR_LENGTH];
  char alias[MAPI_STR_LENGTH];
  char description[1024];
  int link_speed;
  int mpls;
  int vlan;
} mapi_device_info_t;

typedef struct mapi_libfunct_info {
  char name[MAPI_STR_LENGTH]; //Name of function
  char descr[1024]; //Description of function
  char argdescr[MAPI_STR_LENGTH]; //Description of function arguments
  char devtype[MAPI_STR_LENGTH];
} mapi_libfunct_info_t;

typedef struct mapi_lib_info {
  int id; //Library ID
  char libname[MAPI_STR_LENGTH]; //Name of library
  unsigned int functs; //Number of functions in the library
} mapi_lib_info_t;

/*
 * As returned by mapi_stats()
 */
struct mapi_stat {
  unsigned int ps_recv; /* number of packets received */
  unsigned int ps_drop; /* number of packets dropped */
  unsigned int ps_ifdrop; /* drops by interface */
  char hostname[MAPI_STR_LENGTH];
  char dev[MAPI_STR_LENGTH];
};

//Prototype of the mapi_loop callback function
typedef void (*mapi_handler)(const struct mapipkt*);

//Create new mapi flow
extern int mapi_create_flow(const char *dev);

//Create new mapi flow based on a trace file
extern char *mapi_create_offline_device(const char *path,int format);

//Create new mapi flow based on a trace file
extern int mapi_start_offline_device(const char *dev);

//Create new mapi flow based on a trace file
extern int mapi_delete_offline_device(char *dev);

//Apply function to a flow
extern int mapi_apply_function(int fd, const char *funct, ...);

//Connect to a mapi flow
extern int mapi_connect(int fd);

//Get the next packet from a to_buffer function
extern struct mapipkt *mapi_get_next_pkt(int fd,int fid);

//Apply a callback function to all packets in to_buffer (mapi_loop is blocking!!!)
extern int mapi_loop(int fd, int fid, int cnt, mapi_handler);

//Read result from a function
//This should be changed to:
extern mapi_results_t *mapi_read_results(int fd, int fid);

//Close a mapi flow
extern int mapi_close_flow(int fd);

//Read the last error-code set by mapid or mapi-api
//err_no and errorstr should be allocated, the function won't allocate memory
//errorstr is always < 512 bytes
extern int mapi_read_error(int *err_no, char *errorstr);


//Get information on hardware-devices
extern int mapi_get_device_info(int devicenumber, mapi_device_info_t *info);
extern int mapi_get_next_device_info(int devicenumber, mapi_device_info_t *info);

//Get information on loaded libraries
extern int mapi_get_library_info(int libnum, mapi_lib_info_t *info);
extern int mapi_get_next_library_info(int libnum, mapi_lib_info_t *info);
extern int mapi_get_libfunct_info(int libnum, int fnum, mapi_libfunct_info_t *info);
extern int mapi_get_next_libfunct_info(int libnum, int fnum, mapi_libfunct_info_t *info);

//Get information about a flow
extern int mapi_get_flow_info(int fd, mapi_flow_info_t *info);
//Get information about next flow with flow descriptor>fd
extern int mapi_get_next_flow_info(int fd, mapi_flow_info_t *info);

//Get stats about an interface
extern int mapi_stats(const char *dev, struct mapi_stat *stats);

//DiMAPI centric functions
extern int mapi_get_scope_size(int fd);
extern int mapi_is_remote(int fd);

//Get information about a function applied to a flow
extern int mapi_get_function_info(int fd, int fid, mapi_function_info_t *info);
//Get information about a function applied to a flow
extern int mapi_get_next_function_info(int fd, int fid, mapi_function_info_t *info);
#endif
