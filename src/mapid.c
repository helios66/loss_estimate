#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <dlfcn.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/types.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#include "mapid.h"
#include "mapiipc.h"
#include "mapi_errors.h"
#include "flist.h"
#include "parseconf.h"
#include "debug.h"
#include "log.h"
#include "printfstring.h"
#include "pidfile.h"

#define PIDFILE "/var/run/mapid.pid"

static char daemonize = 0;

/* IPC */
#define BACKLOG 16		// how many peding connections socket queue will hold
static int listenerfd; // listening socket descriptor
static int newfd; // newly accept()ed socket descriptor

#define BUFSIZE 2048

static int mapid_get_errno(int fd);
static int deviceid = 1;
static int flowlist_lock = 0;
static int clientlist_lock = 0;

typedef struct _mapidrv mapidrv;

//Structure that stores information about open flows in mapid
struct flow {
	int id; //ID of IPC communication
	int fd; //Flow descriptor
	uid_t uid; //UID of user
	mapidrv *drv; //Pointer to driver which is used by the flow
	int offline;

};

//Structure that stores information about a client process
struct client {
	int pid; //client PID
	int sock; //socket descriptor
	flist_t *flowlist;
	flist_t *devicelist;
	int numdevs;
	int numflows; //number of flows so far
};

typedef struct function {
	void* function;
	int flowid;
	int functid;
	int pid;
} function_t;

struct _mapidrv {
	mapidrv *next;
	void *handle;
	char *device;
	char *alias;
	int format;
	int devid;
	char *name;
	int offline;
	int active;
	mapi_offline_device_status_t offline_status;
	char* description;
	char *trace_dir;
	int link_speed;
	int mpls;
	int vlan;
};

int (*mapidrv_create_flow)(int devid, int fd, char **devtype);
int (*mapidrv_stats)(int devid, char **devtype, struct mapi_stat *stats);

int (*mapidrv_close_flow)(int devid, int fd);
int
		(*mapidrv_apply_function)(int devid, int fd, int flags, char *function,
				...);
int (*mapidrv_read_results)(int devid, int fd, int fid, void *result);
int (*mapidrv_connect)(int devid, int fd);
int (*mapidrv_start_offline_device)(int devid);
int (*mapidrv_get_errno)(int devid, int fd);
mapid_funct_info_t *(*mapidrv_get_flow_functions)(int devid, int fd);
int (*mapidrv_load_library)(char *lib);
int (*mapidrv_add_device)(char *devname, int file, int devid,
		global_function_list_t* gflist, void *extra_param);
int (*mapidrv_get_flow_info)(int devid, int fd, mapi_flow_info_t * info);
int (*mapidrv_delete_device)(int devid);
unsigned char* (*mapidrv_get_lib_name)(int libnumber);

static int get_format(char *format);

static unsigned flows = 0; // number of currently registered flows
static unsigned fdseed = 0; // flow descriptor seed (always increases)

static flist_t *flowlist= NULL; // registered flows

static flist_t *clientlist= NULL; // registered clients (processes)
static mapidrv *drvlist= NULL;
static int running_shutdown = 0;

static void *get_drv_funct(void *drv, const char *funct);

static global_function_list_t* gflist;

static char* mapidsocket;
static char* mapid_conf;

int log_fd_info = -1; // support for logging to file

static void mapid_shutdown(int data) {
	flist_node_t *cur;
	struct client *cl;
	mapidrv *drv = drvlist;

	/* espenb TODO: use lock mechanisms instead 
	 * each thread receives signals, only one thread must execute
	 * shutdown, only one shutdown necessary
	 */
	if (running_shutdown != 0)
		return;
	running_shutdown = 1;

	//we don't want funny things to happen while freeing memory
	signal(SIGTERM, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT, SIG_IGN);

	printf("Closing operations\n");
	//Unload drivers
	while (drv) {
		drvlist = drvlist->next;
		mapidrv_delete_device = get_drv_funct(drv->handle,
				"mapidrv_delete_device");
		if (mapidrv_delete_device)
			mapidrv_delete_device(drv->devid);

		/* if we close, we lose the symbol information associated with drivers 
		 * when running valgrind.
		 */
#ifndef VALGRIND
		printf("!!dlclose\n");
		dlclose(drv->handle);
#endif
		free(drv->device);
		if (drv->description!=NULL)
			free(drv->description);
		if (drv->name)
			free(drv->name);
		//if(drv->alias != NULL)
		//free(drv->alias);
		free(drv);
		drv = drvlist;
	}

	//Remove flowlist
	flist_destroy(flowlist);
	free(flowlist);

	//Remove clientlist
	cur = flist_head(clientlist);
	while (cur) {
		cl = flist_data(cur);
		flist_destroy(cl->flowlist);
		free(cl->flowlist);
		cur = flist_next(cur);
	}
	flist_destroy(clientlist);
	free(clientlist);

	free(gflist->fflist);
	free(gflist);
	free(mapidsocket);
	free(mapid_conf);

	if (log_to_file) {
		daemon_terminated(log_fd_info, "MAPID", daemonize, 0);
		daemon_terminated(log_fd_debug, "MAPID", daemonize, 0);
	}

	if (log_to_syslog) {
		log_message("MAPID was terminated %s%s",
				daemonize ? " ( was running as daemon )" : "");
		closelog(); // closes the descriptor being used to write to the system logger
	}
	//release socket resources
	unlink(mapidsocket);
	close(listenerfd);
	close(newfd);

	running_shutdown = 2;
	printf("mapid terminated\n");
	exit((data == 0) ? EXIT_FAILURE : EXIT_SUCCESS);
}

// sends an IPC message back to the client
static void mapiipc_daemon_write(struct mapiipcbuf *qbuf, int socket) {
	if (send(socket, qbuf, sizeof(struct mapiipcbuf), 0) == -1) {
		DEBUG_CMD(Debug_Message("mapiipc_daemon_write - send:  %s",
				strerror(errno)));
	}
}

// report error over IPC
static void report_error(int err_no, int pid, int sock) {
	struct mapiipcbuf buf;
	buf.mtype = pid;
	buf.cmd = ERROR_ACK;
	buf.remote_errorcode=err_no;
	buf.fd = 0;
	mapiipc_daemon_write((struct mapiipcbuf *) &buf, sock);
	return;
}

/*
 static int 
 funct_compare(void* testee, void* tester)
 {
 if( ( ((function_t*)testee)->flowid == ((int*)tester)[0]) && (((function_t*)testee)->functid == ((int*)tester)[1]) && ( ((function_t*)testee)->pid == ((int*)tester)[2] ) )
 {
 return 0;
 
 }
 else if ( ( ((function_t*)testee)->flowid == ((int*)tester)[0]) && (((function_t*)testee)->functid == ((int*)tester)[1]) && (((int*)tester)[2]==-1 ) )
 {
 return 0;
 } 
 return -1;
 }*/

static void * get_drv_funct(void *drv, const char *funct)
//Returns a pointer to a function inside a driver
//drv = pointer to driver
//funct = name of function
{
	char *msg= NULL;
	void *my_funct = dlsym(drv, funct);

	if (my_funct == NULL) {
		msg = dlerror();
		DEBUG_CMD(Debug_Message("ERROR: get_drv_funct: %s", msg));
		dlclose(drv);
		exit(EXIT_FAILURE);
	}

	return my_funct;
}

static void cleanup_flow(struct flow *f) {
	/* delete device if offline flow */
	if (f->offline != 0) {
		mapidrv_delete_device = get_drv_funct(f->drv->handle,
				"mapidrv_delete_device");
		mapidrv_delete_device(f->drv->devid);
	} else {

		/* Call driver - ignore error */
		mapidrv_close_flow
				= get_drv_funct(f->drv->handle, "mapidrv_close_flow");
		mapidrv_close_flow(f->drv->devid, f->fd);
	}

	// clear mapid flow resources
	f = (struct flow*)flist_remove(flowlist, f->fd);

	flows--;
	//FIX:is it ok here to leave flows-- unprotected by locks?
	/*
	 // clear mapid flow resources
	 f = (struct flow *) flist_remove (flowlist, f->fd);
	 flows--;
	 */
	// _may_ be wrong to deallocate 
	free(f);
}

static mapidrv * get_drv(int fd)
//Returns pointer to driver used by a flow 
//fd = flow descriptor
{
	struct flow *f;
	mapidrv *ret= NULL;

	if ((f=(struct flow*)flist_get(flowlist, fd))!=NULL)
		ret=f->drv;

	/*if ((f = (struct flow *) flist_get (flowlist, fd)) != NULL)
	 ret = f->drv;*/

	return ret;
}

static int get_id(int fd)
//Get IPC id of a flow
//fd = flow descriptor
{
	struct flow *f;
	int ret = -1;

	if ((f=(struct flow*)flist_get(flowlist, fd))!=NULL)
		ret=f->id;

	return ret;
}

static void cmd_load_library(char *lib, int pid, int sock) {
	struct mapiipcbuf buf;
	int err;
	mapidrv *drv = drvlist;

	//Call each driver and tell it to load the new library
	while (drv) {
		mapidrv_load_library = get_drv_funct(drv->handle,
				"mapidrv_load_library");
		err = mapidrv_load_library(lib);
		if (err != 0) {
			DEBUG_CMD(Debug_Message("Could not load library %s", lib));
		}
		drv = drv->next;
	}

	buf.mtype = pid;
	buf.cmd = LOAD_LIBRARY_ACK;
	mapiipc_daemon_write((struct mapiipcbuf *) &buf, sock);
}

/*
 static void
 cmd_get_library_info(int libnumber,int pid, int sock)
 {
 struct mapiipcbuf buf;
 
 if(drvlist!=NULL)
 {
 mapidrv_get_lib_name = get_drv_funct (drvlist->handle, "mapidrv_get_lib_name");
 
 strncpy((char *)buf.data, (char *) mapidrv_get_lib_name(libnumber), sizeof(buf.data));
 
 buf.cmd = GET_LIBRARY_INFO_ACK;
 }
 else
 {
 buf.cmd = ERROR_ACK; 	
 }
 buf.mtype = pid;
 buf.fd = -1;
 
 mapiipc_daemon_write ((struct mapiipcbuf *) &buf, sock);
 }
 */

static void cmd_get_libpath(int pid, int sock)
//Create a new flow
//dev = device
//if = IPC id used to send ack message back to client
{
	struct mapiipcbuf buf;
	char *path, *p;
	static char newpath[BUFSIZE] = { '\0' };
	char *np = newpath;
	char pwd[BUFSIZE];
	int size= BUFSIZE;
	int first = 1;
  conf_category_t *conf;

	buf.cmd = GET_LIBPATH_ACK;

	if (newpath[0] == '\0') {
		if ((conf = pc_load(mapid_conf)) != NULL) {
			path = pc_get_param(pc_get_category(conf, ""), "libpath");

			//Add current path of mapid to relative paths
			if (getcwd(pwd, BUFSIZE) == NULL)
				buf.cmd = GET_LIBPATH_NACK;
			else {
				while ((p = strchr(path, ':')) != NULL) {
					*p = '\0';
					if (!first) {
						*np = ':';
						np++;
					}
					if (path[0] != '/') {
						snprintf(np, size, "%s/", pwd);
						np += strlen(pwd) + 1;
						size -= strlen(pwd) + 1;
					}

					snprintf(np, size, "%s", path);
					np += strlen(path);
					size -= strlen(path);
					path = p + 1;
					first = 0;
				}

				if (!first) {
					*np = ':';
					np++;
				}
				if (path[0] != '/') {
					snprintf(np, size, "%s/", pwd);
					np += strlen(pwd) + 1;
					size -= strlen(pwd) + 1;
				}

				snprintf(np, size, "%s", path);
				np += strlen(path);
				size -= strlen(path);

				//Copy path to buffer
				strncpy((char *)buf.data, newpath, sizeof(char) * 2048);

			}
			pc_close(conf);
		} else {
			buf.cmd = GET_LIBPATH_NACK;
		}
	} else {
		strncpy((char *)buf.data, newpath, sizeof(char) * 2048);
	}

	buf.mtype = pid;
	mapiipc_daemon_write(&buf, sock);
}

static void cmd_get_libs(int pid, int sock) {
	struct mapiipcbuf buf;
	static char path[2048] = { '\0' };
	char *str, *path_;
	long file_size;
  conf_category_t *conf;

	if (path[0] == '\0') {
		if ((conf = pc_load(mapid_conf)) != NULL) {
			str = pc_get_param(pc_get_category(conf, ""), "libs");
			strncpy(path, str, sizeof(char) * 2048);
			strncpy((char *)buf.data, path, sizeof(char) * 2048);
			buf.cmd = GET_LIBS_ACK;

			if (log_to_file) {
				path_ = strdup(path);
				file_size = acquire_write_lock(log_fd_info);
				write_libraries(log_fd_info, path_);
				release_write_lock(log_fd_info, file_size);
				free(path_);
			}
			if (log_to_syslog) {
				path_ = strdup(path);
				syslog_libraries(path_);
				free(path_);
			}
			pc_close(conf);
		} else {
			buf.cmd = GET_LIBS_NACK;
		}
	} else {
		strncpy((char *)buf.data, path, sizeof(char) * 2048);
		buf.cmd = GET_LIBS_ACK;
	}

	buf.mtype = pid;
	mapiipc_daemon_write(&buf, sock);
}

static void cmd_create_flow(char *device, int pid, uid_t uid, int sock) /*removed id, id==pid here */
//Create a new flow
//dev = device
//if = IPC id used to send ack message back to client
{
	struct flow *fl = (struct flow *) malloc(sizeof(struct flow));
	struct client *cl;
	struct mapiipcbuf buf;
	char *devtype;
	mapidrv *drv;
	int err = 0;
	char* dev=device;
	long file_size;

	fl->id = pid;
	fl->fd = ++fdseed;
	fl->drv = NULL;
	fl->uid = uid;
	fl->offline = 0;

	if (running_shutdown)
		err = MAPI_SHUTTING_DOWN;

	//Decide which driver to use
	for (drv = drvlist; drv != NULL; drv = drv->next) {
		if (drv->device != NULL)
			if (strcmp(dev, drv->device) == 0) {
				fl->drv = drv;
				DEBUG_CMD(Debug_Message("Using driver %s for %s", drv->name,
						dev));
				break;
			}
	}

	if (fl->drv == NULL) {
		DEBUG_CMD(Debug_Message("No driver found for %s", dev));
		report_error(MAPID_NO_DRIVER, pid, sock);
		free(fl);
		return;
	}

	++flows; //total number of currently registered flows

	//Calls driver
	if (err == 0) {
		mapidrv_create_flow = get_drv_funct(fl->drv->handle,
				"mapidrv_create_flow");
		err = mapidrv_create_flow(drv->devid, fl->fd, &devtype);

	}

	if (err != 0) {
		/* flow wasn't created */
		/* we can't leave the flow in place, but we need it for errno... */
		/* cleanup? */
		flows--;
		report_error(err, pid, sock);
		free(fl);
		return;
	} else {
		flist_append(flowlist, fl->fd, fl);

		//check if this is the first time we hear from this client
		cl = flist_get(clientlist, pid);
		if (cl == NULL) {
			cl = (struct client *) malloc(sizeof(struct client));
			cl->pid = pid;
			cl->sock = sock;
			// init the list that holds references to the flows of this client
			if ((cl->flowlist = malloc(sizeof(flist_t))) == NULL) {
				DEBUG_CMD(Debug_Message(
						"ERROR: cmd_create_flow - malloc new client struct: %s",
						strerror(errno)));
				exit(EXIT_FAILURE);
			}
			flist_init(cl->flowlist);
			if ((cl->devicelist = malloc(sizeof(flist_t))) == NULL) {
				DEBUG_CMD(Debug_Message(
						"ERROR: cmd_create_flow - malloc new client struct: %s",
						strerror(errno)));
				exit(EXIT_FAILURE);
			}
			flist_init(cl->devicelist);
			cl->numflows = 0;
			cl->numdevs = 0;
			flist_append(clientlist, pid, cl);
		}

		// save a reference to the newly created flow to client's flow list
		cl->numflows++;
		flist_append(cl->flowlist, fl->fd, fl);

		//Send ack back to user
		buf.mtype = pid;
		strcpy((char *)buf.data, devtype);
		buf.cmd = CREATE_FLOW_ACK;
		buf.fd = fl->fd;

		if (log_to_file) {
			file_size = acquire_write_lock(log_fd_info);
			write_to_file(log_fd_info,
					"MAPID: new flow was created ( device: %s, fd: %d ) at ",
					device, fl->fd);
			write_date(log_fd_info);
			write_newline(log_fd_info, "\n");
			release_write_lock(log_fd_info, file_size);
		}
		if (log_to_syslog)
			log_message("new flow was created ( device: %s, fd: %d )", device,
					fl->fd);
	}

	mapiipc_daemon_write(&buf, sock);
}

static void cmd_create_offline_device(char *dev, int format, int pid, int sock)
//Create a new flow
//dev = device
//if = IPC id used to send ack message back to client
{
	struct mapiipcbuf buf;
	mapidrv *drv, *drv2, *lok;
	int err;
	int file;
	struct client *cl;
	char *format_;
	long file_size;

	//Get file descriptor
	buf.mtype = pid;
	buf.cmd = SEND_FD;
	mapiipc_daemon_write((struct mapiipcbuf *) &buf, sock);
	file = mapiipc_read_fd(sock);

	//Decide which driver to use
	for (drv = drvlist; drv != NULL; drv = drv->next) {
		if (drv->format == format) {
			DEBUG_CMD(Debug_Message("Using driver %s for %s", drv->name, dev));
			break;
		}
	}

	if (drv == NULL) {
		DEBUG_CMD(Debug_Message("ERROR: No driver found for %s", dev));
		report_error(MAPID_NO_DRIVER, pid, sock);
		return;
	}

	//Calls driver
	//First create new "device" for the file 
	drv2 = malloc(sizeof(mapidrv));
	drv2->device = malloc(strlen(dev)+7);
	sprintf(drv2->device, "%s@%d", dev, deviceid);
	lok=drvlist;

	while (lok->next!=NULL)
		lok = lok->next;
	lok->next = drv2;
	drv2->next=NULL;
	drv2->handle = drv->handle;
	drv2->name = strdup(drv->name);
	drv2->format = drv->format;
	drv2->devid = -deviceid++;
	drv2->offline = 1;
	drv2->active = 1;
	drv2->description = strdup(drv->description);
	drv2->offline_status = DEVICE_SETUP;

	mapidrv_add_device = get_drv_funct(drv->handle, "mapidrv_add_device");
	err = mapidrv_add_device(dev, file, drv2->devid, gflist,
			&drv2->offline_status);

	if (err != 0) {
		report_error(err, pid, sock);
		return;
	}

	// save a reference to the newly created flow to client's flow list
	cl = flist_get(clientlist, pid);
	if (cl == NULL) {
		cl = (struct client *) malloc(sizeof(struct client));
		cl->pid = pid;
		cl->sock = sock;
		// init the list that holds references to the flows of this client
		if ((cl->flowlist = malloc(sizeof(flist_t))) == NULL) {
			DEBUG_CMD(Debug_Message(
					"ERROR: cmd_create_flow - malloc new client struct: %s",
					strerror(errno)));
			exit(EXIT_FAILURE);
		}
		if ((cl->devicelist = malloc(sizeof(flist_t))) == NULL) {
			DEBUG_CMD(Debug_Message(
					"ERROR: cmd_create_flow - malloc new client struct: %s",
					strerror(errno)));
			exit(EXIT_FAILURE);
		}
		flist_init(cl->flowlist);
		flist_init(cl->devicelist);
		cl->numflows = 0;
		flist_append(clientlist, pid, cl);
	}

	flist_append(cl->devicelist, drv2->devid, drv->handle);
	cl->numdevs++;

	//Send ack back to user
	buf.mtype = pid;
	buf.cmd = CREATE_OFFLINE_DEVICE_ACK;
	strcpy((char *)buf.data, drv2->device);
	buf.fd = -1;

	if (format == 0)
		format_ = strdup("MFF_PCAP");
	else if (format == 1)
		format_ = strdup("MFF_RAW");
	else if (format == 2)
		format_ = strdup("MFF_DAG_ERF");
	else if (format == 4)
		format_ = strdup("MFF_NAPATECH");

	if (log_to_file) {
		file_size = acquire_write_lock(log_fd_info);
		write_to_file(
				log_fd_info,
				"MAPID: new offline device was created ( tracefile: %s, format: %s, device name returned: %s ) at ",
				dev, format_, buf.data);
		write_date(log_fd_info);
		write_newline(log_fd_info, "\n");
		release_write_lock(log_fd_info, file_size);
	}
	if (log_to_syslog)
		log_message(
				"new offline device was created ( tracefile: %s, format: %s, device name returned: %s )",
				dev, format_, buf.data);

	free(format_);
	mapiipc_daemon_write((struct mapiipcbuf *) &buf, sock);
}

static void cmd_start_offline_device(char *dev, int pid, int sock) {
	mapidrv *drv;
	struct mapiipcbuf buf;
	long file_size;

	for (drv = drvlist; drv != NULL; drv = drv->next) {
		if (drv->device != NULL)
			if (strcmp(dev, drv->device) == 0) {
				break;
			}
	}

	if (drv == NULL) {
		DEBUG_CMD(Debug_Message("No driver found for %s", dev));
		report_error(MAPID_NO_DEVICE, pid, sock);
		return;
	}

	mapidrv_start_offline_device = get_drv_funct(drv->handle,
			"mapidrv_start_offline_device");
	if (mapidrv_start_offline_device(drv->devid) != 0) {
		DEBUG_CMD(Debug_Message("No device found for %s", dev));
		report_error(MAPID_NO_DEVICE, pid, sock);
		return;
	}

	buf.mtype = pid;
	buf.cmd = START_OFFLINE_DEVICE_ACK;
	buf.fd = -1;

	if (log_to_file) {
		file_size = acquire_write_lock(log_fd_info);
		write_to_file(log_fd_info, "MAPID: offline device %s was started at ",
				dev);
		write_date(log_fd_info);
		write_newline(log_fd_info, "\n");
		release_write_lock(log_fd_info, file_size);
	}
	if (log_to_syslog)
		log_message("offline device %s was started", dev);

	mapiipc_daemon_write((struct mapiipcbuf *) &buf, sock);
}

static void cmd_delete_offline_device(char *dev, int pid, int sock) {
	mapidrv *drv;
	struct mapiipcbuf buf;
	long file_size;

	for (drv = drvlist; drv != NULL; drv = drv->next) {
		if (drv->device != NULL)
			if (strcmp(dev, drv->device) == 0) {
				break;
			}
	}

	if (drv == NULL) {
		DEBUG_CMD(Debug_Message("No device found for %s", dev));
		report_error(MAPID_NO_DEVICE, pid, sock);
		return;
	}

	if (drv->offline != 0) {
		mapidrv_delete_device = get_drv_funct(drv->handle,
				"mapidrv_delete_device");
		mapidrv_delete_device(drv->devid);
		drv->active=0;
	}

	buf.mtype = pid;
	buf.cmd = DELETE_OFFLINE_DEVICE_ACK;
	buf.fd = -1;

	if (log_to_file) {
		file_size = acquire_write_lock(log_fd_info);
		write_to_file(log_fd_info, "MAPID: offline device %s was deleted at ",
				dev);
		write_date(log_fd_info);
		write_newline(log_fd_info, "\n");
		release_write_lock(log_fd_info, file_size);
	}
	if (log_to_syslog)
		log_message("offline device %s was deleted", dev);
    
  DEBUG_CMD(Debug_Message("Deleted offline device %s", dev));

	mapiipc_daemon_write((struct mapiipcbuf *) &buf, sock);
}

static void cmd_get_function_info(int fd, int fid, int pid, int sock) {
	struct mapiipcbuf buf;
	mapidrv *drv = get_drv(fd);
	mapid_funct_info_t *info;
	mapi_function_info_t i;

	mapidrv_get_flow_functions = get_drv_funct(drv->handle,
			"mapidrv_get_flow_functions");
	info = mapidrv_get_flow_functions(drv->devid, fd);

	//Find correct function
	while (info != NULL)
		if (info->fid != fid)
			info = info->next;
		else
			break;

	if (info != NULL) {
		i.fid = fid;
		strncpy(i.name, info->name, MAPI_STR_LENGTH);
		strncpy(i.libname, info->libname, MAPI_STR_LENGTH);
		strncpy(i.devtype, info->devtype, MAPI_STR_LENGTH);
		i.pkts = *info->pkts;
		i.passed_pkts = *info->passed_pkts;
		memcpy(buf.data, &i, sizeof(mapi_function_info_t));
		buf.cmd = GET_FUNCTION_INFO_ACK;
	} else
		buf.cmd = GET_FUNCTION_INFO_NACK;

	buf.mtype = pid;
	buf.fd = fd;
	mapiipc_daemon_write(&buf, sock);
}

static void cmd_get_next_function_info(int fd, int fid, int pid, int sock) {
	struct mapiipcbuf buf;
	mapidrv *drv = get_drv(fd);
	mapid_funct_info_t *info, *in;
	mapi_function_info_t i;

	if (drv != NULL)
		mapidrv_get_flow_functions = get_drv_funct(drv->handle,
				"mapidrv_get_flow_functions");
	else {
		buf.remote_errorcode=MAPID_NO_DRIVER;
		buf.cmd = GET_FUNCTION_INFO_NACK;
		buf.mtype = pid;
		buf.fd = fd;
		mapiipc_daemon_write(&buf, sock);
		return;
	}
	in = mapidrv_get_flow_functions(drv->devid, fd);
	info = NULL;

	//Find correct function
	while (in != NULL) {
		if (in->fid > fid)
			if (info == NULL || info->fid > in->fid)
				info = in;
		in = in->next;
	}

	if (info != NULL) {
		i.fid = info->fid;
		strncpy(i.name, info->name, MAPI_STR_LENGTH);
		strncpy(i.libname, info->libname, MAPI_STR_LENGTH);
		strncpy(i.devtype, info->devtype, MAPI_STR_LENGTH);
		i.pkts = *info->pkts;
		i.passed_pkts = *info->passed_pkts;
		memcpy(buf.data, &i, sizeof(mapi_function_info_t));
		buf.cmd = GET_FUNCTION_INFO_ACK;
	} else
		buf.cmd = GET_FUNCTION_INFO_NACK;

	buf.mtype = pid;
	buf.fd = fd;
	mapiipc_daemon_write(&buf, sock);
}

static void cmd_get_flow_info(int fd, int pid, int sock) {
	mapi_flow_info_t info;
	struct mapiipcbuf buf;
	struct flow *f;
	mapidrv *drv = get_drv(fd);

	f=(struct flow*)flist_get(flowlist, fd);

	mapidrv_get_flow_info = get_drv_funct(drv->handle, "mapidrv_get_flow_info");
	mapidrv_get_flow_info(drv->devid, fd, &info);
	info.uid = f->uid;
	info.devid = drv->devid;
	strcpy(info.device, f->drv->device);

	memcpy(buf.data, &info, sizeof(mapi_flow_info_t));

	buf.mtype = pid;
	buf.fd = fd;
	buf.cmd = GET_FLOW_INFO_ACK;
	mapiipc_daemon_write(&buf, sock);
}

static void cmd_get_device_info(int devid, int pid, int sock) {
	struct mapiipcbuf buf;
	mapi_device_info_t info;
	mapidrv *drv;

	//Find next device
	for (drv = drvlist; drv != NULL; drv = drv->next) {
		if (drv->device != NULL) {
			if (drv->devid==devid) {
				info.id=drv->devid;
				strncpy(info.name, drv->name, MAPI_STR_LENGTH*sizeof(char));
				strncpy(info.device, drv->device, MAPI_STR_LENGTH*sizeof(char));
				if (drv->alias!=NULL)
					strncpy(info.alias, drv->alias, MAPI_STR_LENGTH*sizeof(char));
				strncpy(info.description, drv->description, 1024*sizeof(char));
				info.link_speed=drv->link_speed;
				info.mpls=drv->mpls;
				info.vlan=drv->vlan;

				memcpy(buf.data, &info, sizeof(mapi_device_info_t));

				buf.mtype = pid;
				buf.fd = devid;
				buf.cmd = GET_DEVICE_INFO_ACK;
				mapiipc_daemon_write(&buf, sock);
				return;
			}

		}
	}
	//Send back error message
	buf.mtype = pid;
	buf.fd = devid;
	buf.cmd = GET_DEVICE_INFO_NACK;
	mapiipc_daemon_write(&buf, sock);
}

static void cmd_get_next_device_info(int devid, int pid, int sock) {
	struct mapiipcbuf buf;
	mapi_device_info_t info;
	mapidrv *drv;

	//Find next device
	for (drv = drvlist; drv != NULL; drv = drv->next) {
		if (drv->device != NULL) {
			if (drv->devid>devid) {
				info.id=drv->devid;
				strncpy(info.name, drv->name, MAPI_STR_LENGTH*sizeof(char));
				strncpy(info.device, drv->device, MAPI_STR_LENGTH*sizeof(char));
				if (drv->alias!=NULL)
					strncpy(info.alias, drv->alias, MAPI_STR_LENGTH*sizeof(char));
				strncpy(info.description, drv->description, 1024*sizeof(char));
				info.link_speed=drv->link_speed;
				info.mpls=drv->mpls;
				info.vlan=drv->vlan;

				memcpy(buf.data, &info, sizeof(mapi_device_info_t));

				buf.mtype = pid;
				buf.fd = devid;
				buf.cmd = GET_DEVICE_INFO_ACK;
				mapiipc_daemon_write(&buf, sock);
				return;
			}

		}
	}
	//Send back error message
	buf.mtype = pid;
	buf.fd = devid;
	buf.cmd = GET_DEVICE_INFO_NACK;
	mapiipc_daemon_write(&buf, sock);
}

static void cmd_get_next_flow_info(int fd, int pid, int sock) {
	flist_node_t *f;
	int d = 0;
	struct mapiipcbuf buf;

	while(__sync_lock_test_and_set(&flowlist_lock,1));

	f=flist_head(flowlist);
	//Loop through flows to find the next one
	while (f!=NULL) {
		if (flist_id(f)>fd) {
			if (d==0)
				d=flist_id(f);
			else if (flist_id(f)<d)
				d=flist_id(f);
		}
		f=flist_next(f);
	}

	flowlist_lock = 0;

	if (d != 0)
		cmd_get_flow_info(d, pid, sock);
	else {
		//Send back error message
		buf.mtype = pid;
		buf.fd = fd;
		buf.cmd = GET_FLOW_INFO_NACK;
		mapiipc_daemon_write(&buf, sock);
	}
}

/**
 * closes a flow described by fd
 * if send_reply is non-zero, a response is sent to client's mapi stub,
 * (send_reply=0 is used for local clean-ups)
 */
static void cmd_close_flow(int fd, int pid, int sock, int send_reply) {
	struct flow *f;
	struct client *cl;
	struct mapiipcbuf buf;
	long file_size;

	f=(struct flow*)flist_get(flowlist, fd);

	if (f) {
		/* to avoid reading memory after it's freed */
		int tmpfd = f->fd;
		/* prevent closing flows of other processes */
		if (pid != f->id) {
			DEBUG_CMD(Debug_Message(
					"Proc %d tried to close flow %d, which belongs to proc %d",
					pid, f->fd, f->id));
			report_error(MAPI_INVALID_FLOW, pid, sock);
			return;
		}

		cleanup_flow(f);

		while(__sync_lock_test_and_set(&clientlist_lock,1));
		cl = flist_get(clientlist, pid);
		f = (struct flow *) flist_remove(cl->flowlist, fd);
		cl->numflows--;
		clientlist_lock = 0;

		//send an ACK that flow closed
		if (send_reply) {

			buf.mtype = pid;
			buf.cmd = CLOSE_FLOW_ACK;
			buf.fd = tmpfd;
			mapiipc_daemon_write((struct mapiipcbuf *) &buf, sock);

			if (log_to_file) {
				file_size = acquire_write_lock(log_fd_info);
				write_to_file(log_fd_info, "MAPID: flow %d was closed at ",
						buf.fd);
				write_date(log_fd_info);
				write_newline(log_fd_info, "\n");
				release_write_lock(log_fd_info, file_size);
			}
			if (log_to_syslog)
				log_message("flow %d was closed", buf.fd);
		}
	} else {
		report_error(MAPI_INVALID_FLOW, pid, sock);
	}
}

static void cmd_connect(int fd, int pid, int sock)
//Connect to flow
//fd = flow descriptor
{
	struct mapiipcbuf buf;
	int err = 0;
	mapidrv *drv = get_drv(fd);
	long file_size;

	if (drv == NULL) {
		/* driver not found(should be handled in create_flow), or invalid flow id */
		DEBUG_CMD(Debug_Message("cmd_connect: no driver found"));
		report_error(MAPI_INVALID_FLOW, pid, sock);
		return;
	}

	if (err == 0) {
		mapidrv_connect = get_drv_funct(drv->handle, "mapidrv_connect");
		err = mapidrv_connect(drv->devid, fd);
	}
	if (err != 0) {
		report_error(err, pid, sock);
		return;
	}

	buf.cmd = CONNECT_ACK;
	buf.mtype = get_id(fd); /* should be == pid */
	buf.fd = fd;

	if (log_to_file) {
		file_size = acquire_write_lock(log_fd_info);
		write_to_file(log_fd_info, "MAPID: connect to flow %d at ", fd);
		write_date(log_fd_info);
		write_newline(log_fd_info, "\n");
		release_write_lock(log_fd_info, file_size);
	}
	if (log_to_syslog)
		log_message("connect to flow %d", fd);

	mapiipc_daemon_write((struct mapiipcbuf *) &buf, sock);
}

static void cmd_read_results(int fd, int fid, int pid, int sock)
//Read results from a function
//fd = flow descriptor
//fid = function ID
{
	mapidrv *drv = get_drv(fd);
	mapid_result_t *result;
	struct mapiipcbuf buf;
	int err;
	char *p = (char *)buf.data;

	if (drv == NULL) {
		/* driver not found(should be handled in create_flow), or invalid flow id */
		DEBUG_CMD(Debug_Message("cmd_read_results: no driver found"));
		report_error(MAPI_INVALID_FLOW, pid, sock);
		return;
	}
	mapidrv_read_results = get_drv_funct(drv->handle, "mapidrv_read_results");
	err = mapidrv_read_results(drv->devid, fd, fid, &result);
	if (err != 0) {
		report_error(err, pid, sock);
		return;
	}
	buf.mtype = get_id(fd);
	buf.cmd = READ_RESULT_ACK;
	buf.fd = fd;

	//Copy result data 
	if (result->funct_res_size + 2*sizeof(mapid_shm_t) < DATA_SIZE) {
		memcpy(p, &result->shm, sizeof(mapid_shm_t));
		p += sizeof (result->shm);
		memcpy(p, &result->shm_spinlock, sizeof(mapid_shm_t));
		if (result->funct_res_size > 0) {
			p += sizeof (result->shm);
			memcpy(p, result->funct_res, result->funct_res_size);
		}
		buf.size = result->funct_res_size + 2*sizeof(mapid_shm_t);
	} else {
		//TODO: Return proper error message
	}

	mapiipc_daemon_write(&buf, sock);

}

static void cmd_apply_function(struct mapiipcbuf *qbuf, int pid, int sock)
//Apply function to flow
//qbuf = IPC buffer
//(this function should be changed so that it becomes IPC independent)
{
	int functionid;
	int fd;
	mapidrv *drv;
	mapiFunctArg *args = qbuf->data;
	char *argdescr = (char *)qbuf->argdescr;
	char *function;
	long file_size;

	while (strlen(argdescr) > 0) {
		switch (*argdescr) {
		case 's':
			args += strlen((char *)args) + 1;
			break;
		case 'S': // reference to flows and functions (e.g RES2FILE)
			args += strlen((char *)args) + 1;
			break;
		case 'i':
			args += sizeof(int);
			break;
		case 'r': // reference to a flow
			args += sizeof(int);
			break;
		case 'f': // reference to a fuction
			args += sizeof(int);
			break;
		case 'c':
			args += sizeof(char);
			break;
		case 'l':
			args += sizeof(unsigned long long);
			break;
		case 'u':
			args += sizeof(int);
			break;
		case 'p':
			args += strlen((char *)args) + 1;
			break;
		case 'w':
			qbuf->mtype = get_id(qbuf->fd);
			qbuf->cmd = SEND_FD;
			mapiipc_daemon_write((struct mapiipcbuf *) qbuf, sock);
			fd = mapiipc_read_fd(sock);
			addarg(&args, &fd, INT);
			break;

		default:
			break;
		}
		argdescr++; // move to the next arg
	}

	drv = get_drv(qbuf->fd);
	if (drv == NULL) {
		DEBUG_CMD(Debug_Message(
				"cmd_apply_function: no driver found for fd=%d", qbuf->fd));
		report_error(MAPI_INVALID_FLOW, pid, sock);
		return;
	}
	mapidrv_apply_function = get_drv_funct(drv->handle,
			"mapidrv_apply_function");

	function = strdup(qbuf->function);

	functionid = mapidrv_apply_function(drv->devid, qbuf->fd, APPLY_NORMAL,
			qbuf->function, qbuf->data);

	if (functionid == -1) {
		/* error in mapid */
		report_error(mapid_get_errno(qbuf->fd), pid, sock);
		return;
	}
	qbuf->mtype = get_id(qbuf->fd);
	qbuf->cmd = APPLY_FUNCTION_ACK;
	qbuf->fid = functionid;

	if (log_to_file) {
		file_size = acquire_write_lock(log_fd_info);
		write_to_file(log_fd_info,
				"MAPID: function %s was applyed to flow %d ( fid: %d ) at ",
				function, qbuf->fd, qbuf->fid);
		write_date(log_fd_info);
		write_newline(log_fd_info, "\n");
		release_write_lock(log_fd_info, file_size);
	}
	if (log_to_syslog)
		log_message("function %s was applyed to flow %d ( fid: %d )", function,
				qbuf->fd, qbuf->fid);

	free(function);
	mapiipc_daemon_write((struct mapiipcbuf *) qbuf, sock);
}
/*
 static void
 cmd_read_error (int loc_err, int pid, int sock)
 {
 struct mapiipcbuf qbuf;
 mapiFunctArg *pos;
 struct error_res err;

 if (loc_err == 0)
 translate_errorcode (mapi_get_error (pid), &err);
 else
 {
 mapi_get_error (pid);	// remove possible other errors for this process
 translate_errorcode (loc_err, &err);	// internal mapi.c error, this unsets pid-error for the process
 }
 qbuf.mtype = pid;
 qbuf.cmd = READ_ERROR_ACK;
 pos = qbuf.data;
 qbuf.fd = err.err_no;
 addarg (&pos, err.error_str, STRING);

 mapiipc_daemon_write ((struct mapiipcbuf *) &qbuf, sock);
 free_error (&err);
 }
 */

static void
cmd_stats (char *device, int pid, MAPI_UNUSED uid_t uid, int sock)	/*removed id, id==pid here */
//dev = device
//if = IPC id used to send ack message back to client
{
  struct mapiipcbuf buf;
  char *devtype;
  mapidrv *drv;
  int err = 0;
  char* dev=device;
  struct mapi_stat stats;

  if (running_shutdown)
    err = MAPI_SHUTTING_DOWN;

  //Decide which driver to use
  for (drv = drvlist; drv != NULL; drv = drv->next)
    {
      if (drv->device != NULL)
		if (strcmp (dev, drv->device) == 0)
		  {
		    //DEBUG_CMD(Debug_Message("Using driver %s for %s", drv->name, dev));
		    break;
		  }
    }

  if (drv == NULL)
    {
      DEBUG_CMD(Debug_Message("No driver found for %s", dev));
      report_error (MAPID_NO_DRIVER, pid, sock);
      return;
    }

  //Calls driver
  if (err == 0)
    {
      mapidrv_stats = get_drv_funct (drv->handle, "mapidrv_stats");
      err = mapidrv_stats (drv->devid, &devtype, &stats);
    }

  if (err != 0)
    {
	buf.mtype = pid;
	buf.cmd = MAPI_STATS_ERR;
	buf.remote_errorcode=err;
	buf.fd = 0;
	mapiipc_daemon_write ((struct mapiipcbuf *) &buf, sock);
	return;
    }
  else
    {
      //Send ack back to user
      buf.mtype = pid;
      memcpy ((char *)buf.data, &stats, sizeof(struct mapi_stat));
      buf.cmd = MAPI_STATS_ACK;
      buf.fd = 0;
    }

  mapiipc_daemon_write (&buf, sock);
}

static void mapidcom()
//Communicates with clients through IPC
{
	fd_set active_fd_set; // active file descriptor list
	fd_set read_fd_set; // temp file descriptor list for select()
	int fdmax; // maximum file descriptor number
	int yes = 1; // for setsockopt() SO_REUSEADDR, below
	struct sockaddr_un mapidaddr;
	struct sockaddr_un remoteaddr;
	struct mapiipcbuf qbuf;
	socklen_t addrlen;
	int nbytes, len, s;
	struct client *cl= NULL;
	flist_node_t *tmpnode;
	conf_category_entry_t *cat=NULL;
	char *local;
	struct group *mapi_group;
  conf_category_t *conf;

	mapidsocket=strdup(MAPIDSOCKGLOBAL);

	if ((conf = pc_load(mapid_conf)) != NULL) {
		cat = pc_get_category(conf, "");
		local=pc_get_param(cat, "local");
		if (local!=NULL && strcmp(local, "1")==0) {
			free(mapidsocket);
			mapidsocket=printf_string(MAPIDSOCKHOME, getenv("HOME") );
		}
		pc_close(conf);

	}
	//  create the listener socket
	if ((listenerfd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
		DEBUG_CMD(Debug_Message("ERROR: socket: %s", strerror(errno)));
		exit(EXIT_FAILURE);
	}
	// avoid "address already in use" error message
	if (setsockopt(listenerfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))
			== -1) {
		DEBUG_CMD(Debug_Message("ERROR: setsockopt: %s", strerror(errno)));
		exit(EXIT_FAILURE);
	}
	//  set up the address we will be binding to
	memset(&mapidaddr, 0, sizeof (mapidaddr));
	mapidaddr.sun_family = AF_LOCAL;

	memcpy(mapidaddr.sun_path, mapidsocket, strlen(mapidsocket)+1);
	unlink(mapidsocket);

	len = sizeof mapidaddr.sun_family + strlen(mapidaddr.sun_path);
	if (bind(listenerfd, (struct sockaddr *) &mapidaddr, len)) {
		DEBUG_CMD(Debug_Message("ERROR: bind: %s", strerror(errno)));
		exit(EXIT_FAILURE);
	}

	// allow any member of our own group to connect
	chmod(mapidsocket, S_IRWXU | S_IRWXG);

	// if a mapi user group exists, set group permissions accordingly,
	// otherwise the group ID will be equal to the user ID of the user that
	// invoked mapid
	mapi_group = getgrnam(MAPI_GROUP_NAME);
	if (mapi_group != NULL) {
		chown(mapidsocket, -1, mapi_group->gr_gid);
	}

	if (listen(listenerfd, BACKLOG) == -1) {
		DEBUG_CMD(Debug_Message("ERROR: listen: %s", strerror(errno)));
		exit(EXIT_FAILURE);
	}

	FD_ZERO (&active_fd_set);
	// add the listener to the active set
	FD_SET (listenerfd, &active_fd_set)
;
  // keep track of the biggest file descriptor
  		fdmax = listenerfd; // so far, it's just this one

	// wait for commands from the mapi stub, for ever...
	while (1) {
		read_fd_set = active_fd_set; // copy it
		if (select(fdmax + 1, &read_fd_set, NULL, NULL, NULL) == -1) {
			DEBUG_CMD(Debug_Message("ERROR: select: %s", strerror(errno)));
			break;
		}

		// run through the existing connections
		for (s = 0; s <= fdmax; s++) {
			if (FD_ISSET (s, &read_fd_set)) {

				// connection on the original listener socket
				if (s == listenerfd) {
					addrlen = sizeof (remoteaddr);
					if ((newfd = accept(listenerfd,
							(struct sockaddr *) &remoteaddr, &addrlen)) == -1) {
						DEBUG_CMD(Debug_Message("accept: %s", strerror(errno)));
					} else {
						FD_SET (newfd, &active_fd_set)
;						// add to active set
						if (newfd > fdmax)
						{ // keep track of the maximum
							fdmax = newfd;
						}
					}
				}
				// handle data from an existing client
				else
				{
					if ((nbytes = recv (s, &qbuf, MAX_SEND_SIZE, 0)) <= 0)
					{
						if (nbytes == 0)
						{
							// connection closed - find client's pid
							while(__sync_lock_test_and_set(&clientlist_lock,1));
							tmpnode = (flist_node_t *) flist_head (clientlist);

							cl = NULL;
							while (tmpnode != NULL)
							{
								if (((struct client *) tmpnode->data)->sock == s)
								{
									cl = (struct client *) tmpnode->data;
									break;
								}
								tmpnode = flist_next (tmpnode);
							}
							clientlist_lock = 0;

							if (cl == NULL)
							{/* This is not interesting, as it will occur upon requests from clients without flows etc.
							 WARNING_CMD (printf
							 ("WARNING: Zero bytes from socket %d [%s:%d]\n",
							 s, __FILE__, __LINE__));
							 */
								/* shouldn't really exit here? 
								 * this will cause the program to exit on errors with an empty
								 * client-list which isn't really an error (IMHO)
								 */
								//exit(EXIT_FAILURE);
							}
							else
							{
								while(__sync_lock_test_and_set(&clientlist_lock,1));
								//clean up any remaining flows
								tmpnode = (flist_node_t *) flist_head (cl->flowlist);
								while (tmpnode != NULL)
								{
									cleanup_flow ((struct flow *) tmpnode->data);
									tmpnode = flist_next (tmpnode);
								}
								tmpnode = (flist_node_t *) flist_head (cl->devicelist);
								while (tmpnode != NULL)
								{
									mapidrv_delete_device = get_drv_funct (tmpnode->data, "mapidrv_delete_device");
									mapidrv_delete_device (tmpnode->id);
									tmpnode = flist_next (tmpnode);
								}
								flist_destroy (cl->flowlist);
								flist_destroy (cl->devicelist);
								free(cl->devicelist);
								free (cl->flowlist);
								//remove this client from global client list
								free(flist_remove (clientlist, cl->pid));
								clientlist_lock = 0;
							}
						}
						else
						{
							DEBUG_CMD(Debug_Message("WARNING: recv: %s at", strerror (errno)));
						}
						close (s);
						FD_CLR (s, &active_fd_set); // remove it from active set
					}
					else
					{
						// we got some data from a client: process request
						switch (qbuf.cmd)
						{
							case GET_LIBS:
							cmd_get_libs (qbuf.pid, s);
							break;
							case GET_LIBPATH:
							cmd_get_libpath (qbuf.pid, s);
							break;
							case CREATE_FLOW:
							cmd_create_flow ((char *)qbuf.data, qbuf.pid, qbuf.uid, s);
							break;
							case CLOSE_FLOW:
							cmd_close_flow (qbuf.fd, qbuf.pid, s, 1);
							break;
							case GET_FLOW_INFO:
							cmd_get_flow_info (qbuf.fd, qbuf.pid, s);
							break;
							case GET_FUNCTION_INFO:
							cmd_get_function_info (qbuf.fd, qbuf.fid, qbuf.pid, s);
							break;
							case GET_NEXT_FUNCTION_INFO:
							cmd_get_next_function_info (qbuf.fd, qbuf.fid, qbuf.pid, s);
							break;
							case GET_NEXT_FLOW_INFO:
							cmd_get_next_flow_info (qbuf.fd, qbuf.pid, s);
							break;
							case GET_NEXT_DEVICE_INFO:
							cmd_get_next_device_info (qbuf.fd, qbuf.pid, s);
							break;
							case GET_DEVICE_INFO:
							cmd_get_device_info (qbuf.fd, qbuf.pid, s);
							break;
						case MAPI_STATS:
						  cmd_stats ((char *)qbuf.data, qbuf.pid, qbuf.uid, s);
						  break;
							case APPLY_FUNCTION:
							cmd_apply_function (&qbuf, qbuf.pid, s);
							break;
							case READ_RESULT:
							cmd_read_results (qbuf.fd, qbuf.fid, qbuf.pid, s);
							break;
							case CONNECT:
							cmd_connect (qbuf.fd, qbuf.pid, s);
							break;
							case CREATE_FLOW_ACK:
							case APPLY_FUNCTION_ACK:
							case READ_RESULT_ACK:
							case CONNECT_ACK:
							case CLOSE_FLOW_ACK:
							case SET_AUTHDATA_ACK:
							break;
							case READ_ERROR_ACK:
							break;
							case ERROR_ACK:
							break;
							case CREATE_OFFLINE_DEVICE:
							cmd_create_offline_device ((char *)qbuf.data, qbuf.fid, qbuf.pid, s);
							break;
							case CREATE_OFFLINE_DEVICE_ACK:
							break;
							case START_OFFLINE_DEVICE:
							cmd_start_offline_device ((char *)qbuf.data, qbuf.pid, s);
							break;
							case START_OFFLINE_DEVICE_ACK:
							break;
							case DELETE_OFFLINE_DEVICE:
							cmd_delete_offline_device ((char *)qbuf.data, qbuf.pid, s);
							break;
							case DELETE_OFFLINE_DEVICE_ACK:
							break;
							case CREATE_OFFLINE_FLOW_ACK:
							break;
							case LOAD_LIBRARY:
							cmd_load_library ((char *)qbuf.data, qbuf.pid, s);
							default:
							break;
						}
					}
				}
			}
		} // for
	} // while(1)
}

/* Get error from mapidlib */
static int mapid_get_errno(int fd) {
	mapidrv *drv;
	drv = get_drv(fd);
	if (drv == NULL)
		return MAPI_INVALID_FLOW;
	mapidrv_get_errno = get_drv_funct(drv->handle, "mapidrv_get_errno");
	return mapidrv_get_errno(drv->devid, fd);
}

static void * load_driver(const char *dir, const char *name) {
	char *path, *msg;
	void *handle= NULL;

	if (asprintf(&path, "%s/%s", dir, name) < 0) {
		DEBUG_CMD(Debug_Message("asprintf failed"));
	}
	handle = dlopen(path, RTLD_NOW);
	if (!handle) {
		msg = dlerror();
		DEBUG_CMD(Debug_Message("Error loading driver: %s", msg ? msg
				: "unknown reason"));
	}

	free(path);
	return handle;
}

static int get_format(char *format) {
	if (strcmp(format, MFF_PCAP_STR) == 0)
		return MFF_PCAP;
	else if (strcmp(format, MFF_DAG_ERF_STR) == 0)
		return MFF_DAG_ERF;
	else if (strcmp(format, MFF_NAPATECH_STR) == 0)
		return MFF_NAPATECH;
	else
		return -1;
}

static void * load_drivers() {
	conf_category_entry_t *cat=NULL;
	conf_parameter_t *p;
	char *device= NULL, *driver= NULL, *drvpath= NULL, *format= NULL;
	char *description= NULL, *alias= NULL, *trace_dir= NULL, *link_speed=NULL,
			*devgroupstr=NULL, *mpls=NULL, *vlan=NULL, *local=NULL;
	void *handle;
	mapidrv *drv;
	int err;
  conf_category_t *conf;

	mapidrv *drvlist2= NULL;
	mapidrv *lok= NULL;

	if ((conf = pc_load(mapid_conf)) != NULL) {
		cat = pc_get_category(conf, "");
		local=pc_get_param(cat, "local");

		drvpath = pc_get_param(cat, "drvpath");

		cat = pc_get_category(conf, "driver");

		//Loop through drivers
		while (cat != NULL) {
			device=pc_get_param(cat, "device");
			driver=pc_get_param(cat, "driver");
			description=pc_get_param(cat, "description");
			alias=pc_get_param(cat, "alias");
			trace_dir=pc_get_param(cat, "trace_dir");
			link_speed=pc_get_param(cat, "link_speed");
			devgroupstr=pc_get_param(cat, "devgroup");
			mpls=pc_get_param(cat, "mpls");
			vlan=pc_get_param(cat, "vlan");

			if (device && strlen(device) > 0 &&
			    driver && strlen(driver) > 0) {
				if ((handle = load_driver(drvpath, driver)) != NULL) {
					drv = malloc(sizeof(mapidrv));
					drv->device = strdup(device);
					if (drvlist2!=NULL) {
						lok->next = drv;
						lok = lok->next;
					} else {
						drvlist2 = drv;
						lok = drv;
					}
					drv->next = NULL;
					drv->handle = handle;
					drv->name = strdup(driver);
					drv->format = -1;
					drv->devid = deviceid++;
					drv->offline=0;
					drv->active = 0;
					drv->offline_status = DEVICE_ONLINE;
					if (description!=NULL)
						drv->description = strdup(description);
					else
						drv->description=strdup("No description");

					if (alias!=NULL)
						drv->alias = strdup(alias);
					else
						drv->alias=strdup("No alias");

					if (trace_dir != NULL)
						drv->trace_dir = strdup(trace_dir);
					else
						drv->trace_dir = NULL;

					if (link_speed!=NULL)
						drv->link_speed = atoi(link_speed);
					else
						drv->link_speed = 0;

					if (mpls!=NULL)
						drv->mpls = atoi(mpls);
					else
						drv->mpls = 0;

					if (vlan!=NULL)
						drv->vlan = atoi(vlan);
					else
						drv->vlan = 0;

					//Call driver add_device
					mapidrv_add_device = get_drv_funct(drv->handle,
							"mapidrv_add_device");
					err = mapidrv_add_device(device, -1, drv->devid, gflist,
							drv->trace_dir);
					if (!err)
						drv->active = 1;
					//Quick fix for a bug in the config file parser
					if (format!=NULL) {
						device[0] = '\0';
						driver[0] = '\0';
						if (description!=NULL)
							description[0] = '\0';
					}
				}
			}
			cat = cat->next;
		}

		//Check file formats
		cat = pc_get_category(conf, "format");

		//Loop through drivers
		while (cat != NULL) {
			p = cat->params;
			if ((strcmp(p->name, "format") == 0) && (p->next != NULL)
					&& (strcmp(p->next->name, "driver") == 0)) {
				format = p->value;
				driver = p->next->value;
				if ((p->next->next!=NULL) && (strcmp(p->next->next->name,
						"description") == 0))
					description = p->next->next->value;
				else
					description = NULL;
			} else {
				cat = cat->next;
				continue;
			}

			if (strlen(format) > 0 && strlen(driver) > 0) {
				//Check to see if driver is allready loaded
				for (drv = drvlist2; drv != NULL; drv = drv->next) {
					if (strcmp(driver, drv->name) == 0) {
						drv->format = get_format(format);
						break;
					}
				}
				if (drv == NULL) {
					//Load new driver
					if ((handle = load_driver(drvpath, driver)) != NULL) {
						drv = malloc(sizeof(mapidrv));
						drv->format = get_format(format);
						drv->device = strdup(format);
						if (drvlist2!=NULL) {
							lok->next = drv;
							lok=lok->next;
						} else {
							drvlist2 = drv;
							lok = drv;
						}
						drv->next=NULL;
						drv->handle = handle;
						drv->offline = 1;
						drv->active = 0;
						drv->name = strdup(driver);
						if (description!=NULL)
							drv->description = strdup(description);
						else
							drv->description=strdup("No description");
						if (link_speed!=NULL)
							drv->link_speed = atoi(link_speed);
						else
							drv->link_speed = 0;
						if (mpls!=NULL)
							drv->mpls = atoi(mpls);
						else
							drv->mpls = 0;

						if (vlan!=NULL)
							drv->vlan = atoi(vlan);
						else
							drv->vlan = 0;
					}
				}

				//Quick fix for a bug in the config file parser
				if (format!=NULL) {
					if (device!=NULL)
						device[0] = '\0';
					if (driver!=NULL)
						driver[0] = '\0';
					if (description!=NULL)
						description[0] = '\0';
				}
			}
			cat = cat->next;
		}

		pc_close(conf);
	}
	return drvlist2;
}

static void print_usage(const char *name) {

	printf("Usage: %s [OPTIONS]\n", name);
	printf("  -d, --daemon		Run as a daemon\n");
	printf("  -g, --devgroup	Bind only devices in <devgroup>\n");
	printf("  -s, --syslog		Logging to syslog\n");
	printf("  -v, --version		Display the version number\n");
	printf("  -h, --help		Display this message\n");
}

static void parse_arguments(int argc, char **argv) {

	int c;

	static const char optstring[] = "vhds:";

	static const struct option longopts[] = { { "daemon", no_argument, NULL,
			'd' }, { "syslog", no_argument, NULL, 's' }, { "devgroup",
			required_argument, NULL, 'g' },
			{ "version", no_argument, NULL, 'v' }, { "help", no_argument, NULL,
					'h' }, { NULL, 0, NULL, 0 } };

	while ((c = getopt_long(argc, argv, optstring, longopts, NULL)) != -1) {

		switch (c) {
		case 'd':
			daemonize = 1;
			break;
		case 'v':
			printf("mapid: MAPI v%s\n", PACKAGE_VERSION);
			exit(EXIT_SUCCESS);
			break;
		case 's': // logging to syslog enabled
			log_to_syslog = 1;
			break;
		case 0: // long option without an equivalent short arg
		case 'h':
		case '?':
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}
}

static void remove_pidfile(void)
{
	(void) remove_pid(PIDFILE);
}

static int continue_as_daemon() {
	int nullfd;

	printf("Closing stdin, stdout, stderr and going into background.\n");

	switch (fork()) {
	case 0:
		break;
	case -1:
		DEBUG_CMD(Debug_Message("ERROR: fork() failed %d - %s", errno,
				strerror(errno)));
		return EXIT_FAILURE;
		break;
	default:
		_exit(0);
		break;
	}
	if (setsid() == -1) {
		DEBUG_CMD(Debug_Message("ERROR: setsid() failed %d - %s", errno,
				strerror(errno)));
		return EXIT_FAILURE;
	}

	setpgrp();

	switch (fork()) {
	case 0:
		break;
	case -1:
		DEBUG_CMD(Debug_Message("ERROR: fork() failed %d - %s", errno,
				strerror(errno)));
		return EXIT_FAILURE;
		break;
	default:
		_exit(0);
		break;
	}

	if (!check_pid(PIDFILE)) {
		if (write_pid(PIDFILE)) {
			(void) atexit(remove_pidfile);
		} else {
			printf("Could not write pidfile\n");
		}
	} else {
		/* A mapid already running and owning pidfile */
		printf("A mapid is already running. Leaving pidfile alone\n");
		
	}
	
	chdir("/");

	nullfd = open("/dev/null", O_RDONLY);
	dup2(nullfd, STDIN_FILENO);
	close(nullfd);
	nullfd = open("/dev/null", O_WRONLY);
	dup2(nullfd, STDOUT_FILENO);
	dup2(nullfd, STDERR_FILENO);
	close(nullfd);

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {

	const char *homedir;

	parse_arguments(argc, argv);

	flowlist=malloc(sizeof(flist_t));
	flist_init(flowlist);

	clientlist = malloc(sizeof(flist_t));
	flist_init(clientlist);

	gflist = malloc(sizeof(global_function_list_t));

	gflist->fflist=malloc(sizeof(flist_t));
	flist_init(gflist->fflist);
	gflist->lock = 0;

	homedir = getenv("HOME");
	if (homedir == NULL) {
		fputs("Environment variable HOME not set. Giving up.\n", stderr);
		exit( 1);
	}

	mapid_conf = printf_string( CONFDIR"/"CONF_FILE );
	printf("using %s\n", mapid_conf);

	log_level = get_log_level(mapid_conf); // get log level from mapi.conf

	if (log_to_syslog) // logging to syslog is enabled
		open_syslog(log_level, "MAPID");

	log_to_file = set_logging_to_file(mapid_conf, &log_fd_info, &log_fd_debug); // support for logging to file

	if (log_to_syslog == 0 && log_to_file == 0)
		log_level = LOGGING_DISABLED;

	if (log_to_syslog == 0)
		printf("logging to syslog: disabled\n");
	else
		printf("logging to syslog: enabled - LogLevel: %d\n", log_level);

	if (log_to_file) {
		daemon_started(log_fd_info, "MAPID", daemonize, 0);
		daemon_started(log_fd_debug, "MAPID", daemonize, 0);
	}

	if (log_to_syslog)
		log_message(
				"MAPID was started %s%s",
				daemonize ? " ( is running as daemon )" : "");
	drvlist = load_drivers();

	if (drvlist == NULL) {
		DEBUG_CMD(Debug_Message("ERROR: No MAPI drivers found"));
		exit(EXIT_FAILURE);
	}

	// Grab some signals so we can mapid_shutdown gracefully
	signal(SIGTERM, mapid_shutdown);
	signal(SIGQUIT, mapid_shutdown);
	signal(SIGINT, mapid_shutdown);

	if (daemonize)
		continue_as_daemon();

	mapidcom();

	mapid_shutdown(0);
	// wait for shutdown to finish
	// espenb TODO: use pthread_cond_wait (or similar) instead
	while (running_shutdown != 2)
		usleep(10000);
	return 0;
}
