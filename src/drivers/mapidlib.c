#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <grp.h>
#include "mapidlib.h"
#include "mapilibhandler.h"
#include "mapidflib.h"
#include "parseconf.h"
#include "mapidevices.h"
#include "debug.h"
#include "printfstring.h"
#include "mapi_errors.h"
#include "../trackflib/trackflib.h"

//Stores information about flows in mapidlib
typedef struct mapidlibflow {
	int fd;
	//  short active;
	enum mapi_flow_status status;
	short delete;
	flist_t *functionlist;
	flist_t *procfunctionlist;
	mapid_funct_info_t *funct_info_list;
	mapid_hw_info_t *hwinfo; //Information about hardware using mapidlib
	//seems unused: char devtype[MAPI_STR_LENGTH];
	void* adapterinfo; //Pointer to adapter specific information
	char *shm; //Pointer to start of shared memory
	unsigned long long shm_size; //Size of shared memory
	key_t shm_key;
	int shm_id;
	char shm_fname[MAPI_STR_LENGTH];
	time_t start;
	time_t end;
	int err_no;
	short modifies; //1 if a function in the flow modifies packets
	unsigned char *mod_pkt; //Modified packet
	mapid_pkthdr_t mod_pkt_head;

} mapidlibflow_t;

#define NIC_PKTCAP_LEN 1514
unsigned char modified_packet_buf[NIC_PKTCAP_LEN];

static short libs_loaded=0; //1 if function libraries are loaded
static char *libpath;

static void add_funct_info(int fid, mapiFunctArg *fargs,
		mapidflib_function_instance_t *f, mapid_funct_info_t **flist);
static void free_sharedmem(struct mapidlibflow *f);
static void free_functionlist(struct mapidlibflow *f);
static char* mapid_conf;

int mapid_init(mapidlib_instance_t *i)

//Set hw info
//infor = pointer to info
{
	char buf[1024], *str, *s;
	char pathname[MAPI_STR_LENGTH];
	int fd;
	struct group *mapi_group;
	struct shmid_ds shm_data;
  conf_category_t *conf;

	i->flowlist=malloc(sizeof(flist_t));
	flist_init(i->flowlist);
	i->fcount=1;

	if (!libs_loaded) {
		mapid_conf = printf_string( CONFDIR"/"CONF_FILE );

		//Load function libraries
		if ((conf = pc_load(mapid_conf)) != NULL) {
			if ((str = pc_get_param(pc_get_category(conf, ""), "libs")) == NULL) {
				DEBUG_CMD(Debug_Message("WARNING: %s - cannot find libs entry",
						CONF_FILE));
				fflush(stdout);
				exit(1);
			}
			strncpy(buf, str, 1024);

			if ((libpath=pc_get_param(pc_get_category(conf, ""), "libpath")) == NULL) {
				DEBUG_CMD(Debug_Message(
						"WARNING: %s - cannot find libpath entry", CONF_FILE));
				fflush(stdout);
				exit(1);
			}
			str=buf;
			while ((s=strchr(str, ':'))!=NULL) {
				*s='\0';
				mapilh_load_library(libpath, str);
				str=s+1;
			}
			mapilh_load_library(libpath, str);
			pc_close(conf);
			libs_loaded=1;
		}
		free(mapid_conf);
	}

	//Initialized spinlock in shared memory
	//Allocate shared memory
	strncpy(pathname, FUNCTION_SHM_TEMPLATE, MAPI_STR_LENGTH);
	if (mktemp(pathname)==NULL)
		return MDLIB_SHM_ERR;

	umask(017);
	if ((fd=open(pathname, O_CREAT|O_EXCL, FUNCTION_SHM_PERMS))<0)
		return MDLIB_SHM_ERR;
	else
		close(fd);

	strncpy(i->shm_spinlock_fname, pathname, MAPI_STR_LENGTH);

	if ((i->shm_spinlock_key=ftok(pathname, FUNCTION_SHM_PROJECT_ID))<0)
		return MDLIB_SHM_ERR;

	if ((i->shm_spinlock_id=shmget(i->shm_spinlock_key,
			sizeof(pthread_spinlock_t), FUNCTION_SHM_PERMS | IPC_CREAT)) < 0)
		return MDLIB_SHM_ERR;

	if ((i->shm_spinlock=shmat(i->shm_spinlock_id,NULL,0))==(void *) -1)
		return MDLIB_SHM_ERR;

	// if a mapi user group exists, set group permissions accordingly,
	// otherwise the group ID will be equal to the user ID of the user that
	// invoked mapid
	mapi_group = getgrnam(MAPI_GROUP_NAME);
	if (mapi_group != NULL) {
		if (shmctl(i->shm_spinlock_id, IPC_STAT, &shm_data) != 0) {
			DEBUG_CMD(Debug_Message(
					"WARNING: shmctl IPC_STAT of %d failed (%s)",
					i->shm_spinlock_id, strerror(errno)));
		}
		shm_data.shm_perm.gid = mapi_group->gr_gid;
		if (shmctl(i->shm_spinlock_id, IPC_SET, &shm_data) != 0) {
			DEBUG_CMD(Debug_Message(
					"WARNING: shmctl IPC_SET of %d failed (%s)",
					i->shm_spinlock_id, strerror(errno)));
		}
	}

	//Initialize spinlock
	if(pthread_spin_init(i->shm_spinlock, PTHREAD_PROCESS_SHARED) != 0)
		return MDLIB_SHM_ERR;
	i->shm_spinlock_size=sizeof(pthread_spinlock_t);

	return 0;
}
;

//Function that can be used by MAPI functions for adding new functions to the flow
static int mapid_add_funct(mapidlib_instance_t *i, int fd, char *funct, ...) {
	//  struct mapidlibflow * fl=flist_get(i->flowlist,fd);
	struct mapidlibflow * fl=flist_get(i->flowlist, fd);
	mapidflib_function_def_t *fdef=mapilh_get_function_def(funct,
			fl->hwinfo->devtype);
	char *argdescr_ptr;
	int tmp;
	unsigned long long ltmp;
	char ctmp;
	va_list vl;
	mapiFunctArg *pos;
	mapiFunctArg args[FUNCTARGS_BUF_SIZE];

	pos=args;

	va_start(vl,funct);

	if (strncmp(fdef->argdescr, "", 1)) { // there are some args
		argdescr_ptr = fdef->argdescr;
		while (strlen(argdescr_ptr) > 0) {
			switch (*argdescr_ptr) {
			case 's':
				addarg(&pos, va_arg(vl, char*), STRING);
				break;
			case 'i':
				tmp = va_arg(vl, int);
				addarg(&pos, &tmp, INT);
				break;
			case 'c':
				ctmp = va_arg(vl, int); //`char' is promoted to `int' when passed through `...'
				addarg(&pos, &ctmp, CHAR);
				break;
			case 'l':
				ltmp = va_arg(vl, unsigned long long);
				addarg(&pos, &ltmp, UNSIGNED_LONG_LONG);
				break;
			default:
				return -1;
				break;
			}
			argdescr_ptr++; // move to the next arg
		}
	}

	return mapid_apply_function(i, fd, funct, args, APPLY_NORMAL);
}

static void fix_funct_ref(global_function_list_t *gflist,
		mapidflib_function_t *ifunct) {
	flist_node_t *flow;
	flist_node_t *fnode;
	flist_t *functions;
	mapidflib_function_t *funct;

	//Loop through all flows
	for (flow=flist_head(gflist->fflist); flow!=NULL; flow=flist_next(flow)) {
		functions=((mapid_flow_info_t*)flist_data(flow))->flist;
		if (functions==NULL)
			continue;

		for (fnode=flist_head(functions); fnode!=NULL; fnode=flist_next(fnode)) {
			funct=(mapidflib_function_t*)flist_data(fnode);
			if (funct->instance==ifunct->instance) {
				while(__sync_lock_test_and_set(&(gflist->lock),1));
				funct->ref=0;
				ifunct->ref=1;
				funct->instance->refcount--;
				gflist->lock = 0;
				DEBUG_CMD(Debug_Message("Fixed reference for function %d",
						funct->fid));
			}
		}
	}
}

//Deletes a flow and frees all resources allocated by the flow
static void delete_flow(mapidlib_instance_t *i, struct mapidlibflow *flow) {
	struct mapidlibflow *f;
	void* temp=NULL;
	flist_t *functions;
	flist_node_t *funct_node;
	mapidflib_function_t *funct;

	DEBUG_CMD(Debug_Message("Deleting flow %d", flow->fd));

	temp = (void*)flist_get(flow->hwinfo->gflist->fflist, flow->fd); // global optimization

	if (!temp) {
		DEBUG_CMD(Debug_Message("ERROR: Attempt to delete a flow that doesnt exist"));

		// Clean up anyway if necessary
		if (flow->mod_pkt!=NULL)
			free(flow->mod_pkt);
		free(flist_remove(i->flowlist, flow->fd)); // might return NULL, but free(NULL) is safe.

		return;
	}

	((mapid_flow_info_t*)temp)->status = FLOW_CLOSED; // Update global function list
	time(&flow->end); // moved from mapid_close_flow

	functions = ((mapid_flow_info_t*)temp)->flist;

	if (functions!=NULL)
		for (funct_node=flist_head(functions); funct_node!=NULL; funct_node
				=flist_next(funct_node)) {
			funct=(mapidflib_function_t*)flist_data(funct_node);
			if (funct->ref==0 && funct->instance->refcount>0)
				fix_funct_ref(flow->hwinfo->gflist, funct); // Check to see if other functions references this function
		}

	if (flow->mod_pkt!=NULL)
		free(flow->mod_pkt);

	f=flist_remove(i->flowlist, flow->fd);

	free_functionlist(f);
	free_sharedmem(f);
	free(f);
}

//Frees resources allocated by mapidlib, should be called by the drivers when devices are deleted
void mapid_destroy(mapidlib_instance_t *i) {
	flist_node_t *n;
	struct mapidlibflow *f;

	if (i!=NULL) {
		//    pthread_spin_lock(i->shm_spinlock);
		//  n=flist_head(i->flowlist);

		n=flist_head(i->flowlist);

		while (n!=NULL) {
			f=flist_data(n);
			n=flist_next(n);
			delete_flow(i, f);
		}

		flist_destroy(i->flowlist);

		free(i->flowlist);
		//  pthread_spin_unlock(i->shm_spinlock);

		if (shmdt((const void*)i->shm_spinlock)<0) {
			DEBUG_CMD(Debug_Message(
					"WARNING: Could not detach shared mem (%s)",
					strerror(errno)));
		}

		if (shmctl(i->shm_spinlock_id, IPC_RMID, NULL)<0) {
			DEBUG_CMD(Debug_Message("WARNING: Could not free shared mem (%s)",
					strerror(errno)));
		}

		// remove the temporary file that was created by mapid_init for the
		// creation of the shared memory key
		if (unlink(i->shm_spinlock_fname) != 0) {
			DEBUG_CMD(Debug_Message(
					"WARNING: Could not remove shm key file %s (%s)",
					i->shm_spinlock_fname, strerror(errno)));
		}
	} else if (libs_loaded>0) {
		mapilh_free_libraries();
		libs_loaded=0;
	}
}

int mapid_connect(mapidlib_instance_t *i, int fd)
//Connect to a mapi flow
//fd = flow descriptor
{
	//  struct mapidlibflow *flow=flist_get(i->flowlist,fd);
	struct mapidlibflow *flow=flist_get(i->flowlist, fd);

	flist_node_t *n;
	mapidflib_function_t *f;
	mapidflib_function_instance_t *fi;
	unsigned long offset=0;
	int error=0;
	int id, fdn;
	char pathname[MAPI_STR_LENGTH];
	struct group *mapi_group;
	struct shmid_ds shm_data;

	/* NULL-> invalid flow descriptor, set error */
	if (flow==NULL) {
		//we can't know the flow-id, so we can't set an error */
		return -1;
	}

	DEBUG_CMD(Debug_Message("Connect to flow %d", fd));

	/* Don't allow connect() for a second time at the same flow*/
	if (flow->status == FLOW_ACTIVE) {
		return MDLIB_FLOW_ALREADY_ACTIVE;
	}

	if (flow->shm_size>0) {
		//Allocate shared memory
		strncpy(pathname, FUNCTION_SHM_TEMPLATE, MAPI_STR_LENGTH);
		if (mktemp(pathname)==NULL)
			return MDLIB_SHM_ERR;

		umask(017);
		if ((fdn=open(pathname, O_CREAT|O_EXCL, FUNCTION_SHM_PERMS))<0)
			return MDLIB_SHM_ERR;
		else
			close(fdn);

		strncpy(flow->shm_fname, pathname, MAPI_STR_LENGTH);

		if ((flow->shm_key=ftok(pathname, FUNCTION_SHM_PROJECT_ID))<0)
			return MDLIB_SHM_ERR;

		if ((id=shmget(flow->shm_key, flow->shm_size, FUNCTION_SHM_PERMS
				| IPC_CREAT)) < 0)
			return MDLIB_SHM_ERR;

		flow->shm_id=id;

		if ((flow->shm=shmat(id,NULL,0))==(void *) -1)
			return MDLIB_SHM_ERR;

		// if a mapi user group exists, set group permissions accordingly,
		// otherwise the group ID will be equal to the user ID of the user that
		// invoked mapid
		mapi_group = getgrnam(MAPI_GROUP_NAME);
		if (mapi_group != NULL) {
			if (shmctl(id, IPC_STAT, &shm_data) != 0) {
				DEBUG_CMD(Debug_Message(
						"WARNING: shmctl IPC_STAT of %d failed (%s)", id,
						strerror(errno)));
			}
			shm_data.shm_perm.gid = mapi_group->gr_gid;
			if (shmctl(id, IPC_SET, &shm_data) != 0) {
				DEBUG_CMD(Debug_Message(
						"WARNING: shmctl IPC_SET of %d failed (%s)", id,
						strerror(errno)));
			}
		}

		//Initialize memory to 0
		memset(flow->shm, 0, flow->shm_size);
	}

	//Initialize flow functions
	n=flist_head(flow->functionlist);
	while (n && !error) {
		f=flist_data(n);
		fi=f->instance;
		if ((fi->def->restype==MAPIRES_SHM) || (fi->def->restype==MAPIRES_IPC)) {
			/* for MAPIRES_IPC we simply use the shared memory as data container
			 * even when actual data will be sent via socket. */
			//Sett results info
			fi->result.info.shm.key=flow->shm_key;
			fi->result.info.shm.buf_size=flow->shm_size;
			fi->result.info.shm.res_size=fi->result.data_size;
			fi->result.info.shm.offset=offset;
			fi->result.data=flow->shm+offset;
			offset+=fi->result.data_size;

			//Set information about spinlock
			fi->result.info.shm_spinlock.key=i->shm_spinlock_key;
			fi->result.info.shm_spinlock.buf_size=i->shm_spinlock_size;
			fi->result.info.shm_spinlock.offset=0;

		}
		if (fi->def->init!=NULL) {
			DEBUG_CMD(Debug_Message("Initializing function %s\tfid=%d",
					fi->def->name, f->fid));
			error=fi->def->init(fi, fd);
		}

		if (error==0) {
			fi->status=MAPIFUNC_INIT;
		} else {
			DEBUG_CMD(Debug_Message("Init error - %d", error));
		}

		if (fi->def->restype==MAPIRES_IPC) {
			fi->result.info.funct_res = fi->result.data;
			fi->result.info.funct_res_size = fi->result.data_size;
		}

		n=flist_next(n);
	}

	if (error) {
		free_functionlist(flow);
		free_sharedmem(flow);
		flow->delete=2;
		return error;
	}

	//Allocate buffer for modified packets
	flow->mod_pkt = malloc(sizeof(char) * flow->hwinfo->cap_length+64);

	flow->status = FLOW_ACTIVE;
	//Update global function list
	((mapid_flow_info_t*)flist_get(flow->hwinfo->gflist->fflist,flow->fd))->status=FLOW_ACTIVE;

	time(&flow->start);

	return 0;
}

int mapid_add_flow(mapidlib_instance_t *i, int fd, mapid_hw_info_t* hwinfo,
		void *info)
//Add new flow
//fd = flow descriptor
//info = adapter specific info
{
	struct mapidlibflow* fl;
	mapid_flow_info_t *flow=malloc(sizeof(mapid_flow_info_t));

	fl=malloc(sizeof(struct mapidlibflow));

	fl->fd=fd;
	fl->status=FLOW_INIT;
	fl->delete=0;
	fl->err_no=0;
	fl->shm=NULL;
	fl->shm_size=0;
	fl->shm_fname[0] = '\0';
	fl->adapterinfo=info;
	fl->funct_info_list=NULL;
	fl->mod_pkt=NULL;

	fl->functionlist=malloc(sizeof(flist_t));
	flist_init(fl->functionlist);

	//Add new flow to the global function list
	flow->status=FLOW_INIT;
	flow->flist=fl->functionlist;
	while(__sync_lock_test_and_set(&(hwinfo->gflist->lock),1));
	flist_append(hwinfo->gflist->fflist, fd, flow);
	hwinfo->gflist->lock = 0;

	fl->procfunctionlist=malloc(sizeof(flist_t));
	flist_init(fl->procfunctionlist);

	fl->hwinfo=hwinfo;
	fl->start=0;
	fl->end=0;
	fl->modifies=0;

	flist_append(i->flowlist, fd, fl);

	//  flist_append(i->flowlist,fd,fl);

	DEBUG_CMD(Debug_Message("Added new flow, fd=%d", fd));

	return 0; /* no error possible */
}

/* FIXME:
 * This just scratches the surface of resources which need to be freed. 
 */
static void free_functionlist(struct mapidlibflow *fl) {
	mapidflib_function_t *fn;
	mapid_funct_info_t *fi, *fi2;
	flist_node_t *cur;

	//Remove from ff_list
	while(__sync_lock_test_and_set(&(fl->hwinfo->gflist->lock),1));
	free(flist_remove(fl->hwinfo->gflist->fflist, fl->fd));
	fl->hwinfo->gflist->lock = 0;

	cur=flist_head(fl->functionlist);
	while (cur) {

		fn=flist_data(cur);
		if (fn->instance->def->cleanup!=NULL && fn->instance->status
				==MAPIFUNC_INIT)
			fn->instance->def->cleanup(fn->instance);

		free(fn->instance->def);
		free(fn->instance);
		free(fn);
		cur=cur->next;
	}

	flist_destroy(fl->functionlist);
	free(fl->functionlist);

	fi=fl->funct_info_list;
	while (fi) {
		fi2=fi->next;
		free(fi);
		fi=fi2;
	}

	flist_destroy(fl->procfunctionlist);
	free(fl->procfunctionlist);

}

static void free_sharedmem(struct mapidlibflow *f) {
	if (f->shm_size>0 && f->shm!=NULL) {
		if (shmdt(f->shm)<0) {
			DEBUG_CMD(Debug_Message(
					"WARNING: Could not detach shared mem (%s)",
					strerror(errno)));
		}

		if (shmctl(f->shm_id, IPC_RMID, NULL)<0) {
			DEBUG_CMD(Debug_Message("WARNING: Could not free shared mem (%s)",
					strerror(errno)));
		}

		if (remove(f->shm_fname)<0) {
			DEBUG_CMD(Debug_Message(
					"WARNING: Could not remove semaphore file %s (%s)",
					f->shm_fname, strerror(errno)));
		}
	}
}

int mapid_close_flow(mapidlib_instance_t *i, int fd) {
	struct mapidlibflow *f;

	f=flist_get(i->flowlist, fd);

	if (f==NULL)
		return -1;

	f->status = FLOW_CLOSED; // flow is deleted in mapid_process_pkt, in order to avoid a race condition with process packet thread

	return 0;
}

int mapid_read_results(mapidlib_instance_t *i, int fd, int fid,
		mapid_result_t **result)
//Get pointer to shared memory where results are stored
//fd: flow descriptor
//fid: ID of function
//result: pointer to structure where info about shared memory is stored
{
	flist_t *functs;
	mapidflib_function_t *funct;
	mapidflib_result_t *res;

	struct mapidlibflow *flow=flist_get(i->flowlist, fd);

	functs=((mapid_flow_info_t*)flist_get(flow->hwinfo->gflist->fflist,fd))->flist;

	if (functs==NULL)
		return MDLIB_INVALID_FLID;
	else if ((funct=flist_get(functs, fid))==NULL)
		return MDLIB_INVALID_FUNCID;

	if (funct->instance->def->get_result!=NULL) {
		funct->instance->def->get_result(funct->instance, &res);
		*result=&res->info;
	} else
		*result=&funct->instance->result.info;

	return 0;
}

int mapid_get_flow_info(mapidlib_instance_t *i, int fd, mapi_flow_info_t *info) {
	//  struct mapidlibflow *flow = flist_get(i->flowlist,fd);
	struct mapidlibflow *flow = flist_get(i->flowlist, fd);

	info->fd=flow->fd;
	info->devid=flow->hwinfo->devid;
	info->start=flow->start;
	info->end=flow->end;
	info->status=flow->status;
	info->num_functions=flist_size(flow->functionlist);

	return 0;
}

mapid_funct_info_t* mapid_get_flow_functions(mapidlib_instance_t *i, int fd) {
	//  struct mapidlibflow *flow = flist_get(i->flowlist,fd);

	struct mapidlibflow *flow = flist_get(i->flowlist, fd);
	return flow->funct_info_list;
}

int mapid_apply_function(mapidlib_instance_t *i, int fd, char* function,
		mapiFunctArg *fargs, int flags)
//Apply function to a flow
//fd =flow descriptor
//function = info about function
//fptr = pointer to function
//fargs = pointer to arguments buffer
{
	mapidflib_function_def_t *f2;
	mapidflib_function_instance_t *funct_instance=NULL;
	mapidflib_function_t *funct;
	//  struct mapidlibflow * fl=flist_get(i->flowlist,fd);

	struct mapidlibflow * fl=flist_get(i->flowlist, fd);

	int fid;
	mapidflib_flow_mod_t flow_mod;
	int error=0;
	int c;
	boolean_t similar=FALSE;

	flow_mod.delete_size=0;
	//Get function definition
	f2=mapilh_get_function_def(function, fl->hwinfo->devtype);

	if (f2==NULL) {
		//Change so that it returns error message to the application
		DEBUG_CMD(Debug_Message("ERROR: Could not find/match function %s",
				function));
		error=MDLIB_FUNCTION_NOT_FOUND;
		fl->err_no=error;
		return -1;
	}

	//Create function
	funct=malloc(sizeof(mapidflib_function_t));
	funct->fd=fd;
	funct->fid=i->fcount;

	if (funct_instance==NULL) {
		funct->ref=0;
		//Create new function instance
		funct_instance=malloc(sizeof(mapidflib_function_instance_t));
		funct->instance=funct_instance;
		funct_instance->hwinfo=fl->hwinfo;
		funct_instance->status=MAPIFUNC_UNINIT;
		funct_instance->result.data_size = 0;
		funct_instance->result.info.shm.buf_size = 0;
		funct_instance->result.info.shm.res_size = 0;
		funct_instance->result.info.funct_res_size = 0;
		funct_instance->result.data=NULL;
		funct_instance->internal_data=NULL;
		funct_instance->refcount=0;
		funct_instance->apply_flags = flags;

		funct_instance->def=malloc(sizeof(mapidflib_function_def_t));
		memcpy(funct_instance->def, f2, sizeof(mapidflib_function_def_t));
		memcpy(funct_instance->args, fargs, FUNCTARGS_BUF_SIZE);
		flow_mod.reorder=fid=i->fcount++;
		flow_mod.identical=0;
		flow_mod.delete=NULL;
		flow_mod.delete_size=0;
		flow_mod.add_funct=&mapid_add_funct;
		flow_mod.mi=i;

		//Add function to list
		if (flags & APPLY_INTERNAL)
			flist_prepend(fl->functionlist, fid, funct);
		else
			flist_append(fl->functionlist, fid, funct);
		if (f2->process!=NULL) {
			if (flags & APPLY_INTERNAL)
				flist_prepend(fl->procfunctionlist, fid, funct);
			else
				flist_append(fl->procfunctionlist, fid, funct);
		}

		//Check arguments
		if (f2->instance!=NULL)
			error=f2->instance(funct->instance, fd, &flow_mod);
	}

	if (error==MFUNCT_COULD_NOT_APPLY_FUNCT && strcmp(f2->devtype,
			MAPI_DEVICE_ALL)!=0 && strchr(function, '!')==NULL) {
		//TODO: Add support for optimization
		error=0;
		//Try software function
		DEBUG_CMD(Debug_Message(
				"Trying MAPI_DEVICE_ALL devtype because of failure to instance function %s",
				function));
		f2=mapilh_get_function_def(function, MAPI_DEVICE_ALL);

		if (f2==NULL) {
			//Change so that it returns error message to the application
			DEBUG_CMD(Debug_Message("ERROR: Could not find/match function %s",
					function));
			error=MDLIB_FUNCTION_NOT_FOUND;
		} else {
			flist_remove(fl->functionlist, fid);
			flist_remove(fl->procfunctionlist, fid);
			memcpy(funct_instance->def, f2, sizeof(mapidflib_function_def_t));
			flist_append(fl->functionlist, fid, funct);
			//Check arguments
			if (f2->instance!=NULL)
				error=f2->instance(funct_instance, fd, &flow_mod);

			//Add function to process list
			if (f2->process!=NULL)
				flist_append(fl->procfunctionlist, fid, funct);
		}
	}

	if (error!=0) {
		/* function not initialized, error */
		if (fl==NULL) {
			return -1;
		} else {
			flist_remove(fl->functionlist, fid);
			flist_remove(fl->procfunctionlist, fid);
			fl->err_no=error;
			free(funct_instance->def);
			free(funct_instance);
			free(funct);
			return -1;
		}
	}

	if (!similar) {
		fl->shm_size+=funct->instance->def->shm_size;
		if (funct->instance->def->restype==MAPIRES_SHM)
			funct->instance->result.data_size=funct->instance->def->shm_size;

		if (flow_mod.reorder!=fid) {
			DEBUG_CMD(Debug_Message("REORDER"));
			flist_move_before(fl->functionlist, flow_mod.reorder, fid);
			if (f2->process!=NULL)
				flist_move_before(fl->procfunctionlist, flow_mod.reorder, fid);
		}

		//Check if some functions should be deleted
		if (flow_mod.delete) {
			for (c=0; c<flow_mod.delete_size; c++) {
				DEBUG_CMD(Debug_Message("Deleted function"));
				flist_remove(fl->functionlist, flow_mod.delete[c]);
				//No need to call cleanup since init has not yet been called  
			}
			free(flow_mod.delete);
		}

		//Copy information to funct_info structure
		add_funct_info(fid, fargs, funct->instance, &fl->funct_info_list);

		DEBUG_CMD(Debug_Message("Added function: %s library:%s devtype=%s",
				funct->instance->def->name, funct->instance->def->libname,
				funct->instance->def->devtype));

		if (funct->instance->def->modifies_pkts==1)
			fl->modifies=1;

		strncpy(function, funct->instance->def->devtype, FUNCT_NAME_LENGTH);
	}
	return fid;
}

int mapid_finished(mapidlib_instance_t *i) // XXX is this function essential ???
{
	flist_node_t *n;
	struct mapidlibflow *flow;

	n = flist_head(i->flowlist);
	while (n) {
		flow=flist_data(n);
		flow->status=FLOW_FINISHED;
		//Update global function list
		((mapid_flow_info_t*)flist_get(flow->hwinfo->gflist->fflist,flow->fd))->status
				=FLOW_FINISHED;

		n = flist_next(n);
	}

	return 0;
}

/*mapi_function_def_mini_t*
 mapid_get_function_info(int libnumber,int functionnumber)
 {
 return mapidflib_get_function_info(libnumber, functionnumber);
 }

 char*
 mapid_get_lib_name(int libnumber)
 {
 return mapidflib_get_lib_name(libnumber);
 }

 */
#include <netinet/in.h>
void mapid_process_pkt(mapidlib_instance_t *i, unsigned char* dev_pkt,
		unsigned char* link_pkt, mapid_pkthdr_t* pkt_head)
//Process a single packet by applying functions to it
//pkt = pointer to packet
//pkt_head = pointer to packet header
{
	flist_node_t *n, *n2;
	struct mapidlibflow *flow;
	mapidflib_function_t *funct;
	int ret, devhlength;

	n = flist_head(i->flowlist);

	// a color var to help trackers from continunsly searching application
	// strings 
	pkt_head->color = 0;

	devhlength=link_pkt-dev_pkt;

	while (n) {
		flow=flist_data(n);
		n = flist_next(n);

		if (flow->status==FLOW_ACTIVE) {

			if (flow->modifies==1) {
				memcpy(flow->mod_pkt, dev_pkt, pkt_head->caplen+devhlength);
				memcpy(&flow->mod_pkt_head, pkt_head, sizeof(mapid_pkthdr_t));
			}

			n2=flist_head(flow->procfunctionlist);
			ret=1;
			while (n2 && ret!=0) {
				funct = flist_data(n2);

				if (funct->ref==1)
					ret=funct->instance->ret;
				else {
					if (flow->modifies==1)
						ret=funct->instance->def->process(funct->instance,
								flow->mod_pkt, flow->mod_pkt+devhlength,
								&flow->mod_pkt_head);
					else
						ret=funct->instance->def->process(funct->instance,
								dev_pkt, link_pkt, pkt_head);
#ifdef WITH_FUNCT_STATS
					funct->instance->pkts++;
					if(ret)
					funct->instance->processed_pkts++;
#endif
					funct->instance->ret=ret;
				}
				n2 = flist_next(n2);
			}
		} else if (flow->status == FLOW_CLOSED) { // flow has closed, so we can delete it and deallocate all of its resources
			delete_flow(i, flow);
		}
	}
}

int mapid_get_errno(mapidlib_instance_t *i, int fid) {
	struct mapidlibflow * fl;
	//   fl=flist_get(i->flowlist,fid);
	fl=flist_get(i->flowlist, fid);

	if (fl==NULL)
		return MDLIB_INVALID_FLID;
	return fl->err_no;

}

static void add_funct_info(int fid, mapiFunctArg *fargs,
		mapidflib_function_instance_t *f, mapid_funct_info_t **flist) {
	mapid_funct_info_t *fi =
			(mapid_funct_info_t *)malloc(sizeof(mapid_funct_info_t));
	mapid_funct_info_t *l = *flist;

	fi->fid=fid;
	fi->name=f->def->name;
	fi->libname=f->def->libname;
	fi->devtype=f->def->devtype;
	fi->argdescr=f->def->argdescr;
	strncpy((char *)fi->args, (char *)fargs, FUNCTARGS_BUF_SIZE);
	fi->pkts=&f->pkts;
	fi->passed_pkts=&f->processed_pkts;
	fi->next=NULL;

	if (*flist==NULL)
		*flist=fi;
	else {
		while (l->next!=NULL)
			l=l->next;
		l->next=fi;
	}
}

int mapid_get_devid(mapidlib_instance_t *i, int fd) {
	//  struct mapidlibflow *flow=flist_get(i->flowlist,fd);
	struct mapidlibflow *flow=flist_get(i->flowlist, fd);

	return flow->hwinfo->devid;
}

int mapid_load_library(char *lib) {
	return mapilh_load_library(libpath, lib);
}

