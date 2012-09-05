#ifndef MAPI_LOCAL_H
#define MAPI_LOCAL_H 1

#include <pthread.h>
#include "mapiipc.h"
#include "flist.h"

void mapi_init();

//Buffer that is sent to/from mapi and mapid
struct mapiipcbuf {
  long mtype;
  mapiipcMsg cmd;
  int fd;
  char function[FUNCT_NAME_LENGTH];
  int fid;
  int size;
  int pid; /* needed to identify target mtype, to send errors when invalid flow-id's are given, when no flow-id is made,... */
  uid_t uid; //UID of the user running the application
  unsigned char data[DATA_SIZE];
  unsigned char argdescr[ARG_LENGTH];
  int remote_errorcode;
};

typedef struct flowdescr {
  int fd;
  int file;             // file descriptor for offline flows
  int fds[256];         // file descriptors
  int numfd;            // number of file descriptors
  char *devtype;

  char *shm_base;
  pthread_spinlock_t *shm_spinlock;
  flist_t *flist;
  unsigned char is_connected;   // this should be 1 if the flow is connected 0 otherwise
  int format;                   // this should be MFF_PCAP or MFF_DAG_ERF if the flow is offline, -1 otherwise 
} flowdescr_t;

//IPC calls

//Initialize IPC functions
int mapiipc_client_init(void);
// FIXME: this is not ever implemented or used?
//void mapiipc_daemon_init(void);

//Initialize IPC variables
int mapiipc_set_socket_names(char *socket, char *socketglobal);

//Sends an IPC message
int mapiipc_write(struct mapiipcbuf *qbuf);
//Reads an IPC message. Blocking call.
int mapiipc_read(struct mapiipcbuf *qbuf);


//Send a file handle
int mapiipc_send_fd(int sendfd);
//receive a file handle
int mapiipc_read_fd();

//Relase socket resources
void mapiipc_client_close(void);
// FIXME: also not in use? see above
//void mapiipc_daemon_close(void);


#endif
