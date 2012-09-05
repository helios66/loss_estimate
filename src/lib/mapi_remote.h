#ifndef MAPI_REMOTE_H
#define MAPI_REMOTE_H 1

#include <pthread.h>
#include <semaphore.h>
#include "flist.h"
#include "mapiipc.h"

#ifdef DIMAPISSL
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#else
#include <ssl.h>
#include <err.h>
#endif /* HAVE_OPENSSL */
#endif /* DIMAPISSL */

void dmapi_init();

#ifdef DIMAPISSL
struct overload {
  SSL * connection;
  int sock;
};
#endif

//holds info about a remote mapid
struct host {
  char *hostname;
  int port;
  int sockfd;
#ifdef DIMAPISSL
  SSL *con;
  SSL_CTX *ctx;
#endif
  int num_flows;  // to know when to close the socket
  flist_t *flows;
  flist_t *functions;
  pthread_t *comm_thread; // communication thread
  flist_t *stats; //for mapi_stats
};

//Buffer that is sent to/from mapi and agent
struct dmapiipcbuf {
  unsigned int length;
  mapiipcMsg cmd;
  int fd;
  int fid;
  unsigned long long timestamp;
  char data[DIMAPI_DATA_SIZE];
};

#define BASIC_SIZE (sizeof(struct dmapiipcbuf) - DIMAPI_DATA_SIZE)
#define PKT_LENGTH 131072 //pkt info and actual pkt

typedef struct host_flow {
  struct host *rhost;
  char *dev;
  char *devtype;
  int scope_fd;
  int fd; //fd of flow in the mapid of host
  int id;
#ifdef DIMAPISSL
	SSL *con_asyn;
	SSL_CTX *ctx_asyn;
#endif
  struct dmapiipcbuf *dbuf; //buffer for writting results from this host -for this flow-
  struct mapipkt *pkt;
  flist_t *functions; //holds all fids for this host_flow
} host_flow;

typedef struct remote_flowdescr {
  int fd; // 'scope' fd
  int scope_size;
  flist_t *host_flowlist;
  flist_t *pkt_list;  //FIFO list for get_next_pkt
  sem_t fd_sem;
  sem_t pkt_sem;
  flist_t *function_res;
  unsigned char is_connected; // This should be 1 if the flow is connected 0 otherwise
  struct mapipkt *pkt;
} remote_flowdescr_t;

//dmapi centric funcs
extern int mapi_is_sensor_down(int fd);

//dmapi ipc functions and ipcbuffer
int mapiipc_remote_init(struct host *h);
int mapiipc_remote_write(struct dmapiipcbuf *dbuf, struct host *h);
int mapiipc_remote_write_to_all(remote_flowdescr_t *rflow);
void mapiipc_remote_close(struct host *h);
void *mapiipc_comm_thread(void *host);

//Read "n" bytes from a socket.
#ifdef DIMAPISSL
ssize_t SSL_readn(SSL *con, void *vptr, size_t n);
#else
ssize_t readn(int fd, void *vptr, size_t n);
#endif

#endif
