#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <netinet/in.h>
#include "mapi.h"
#include "mapidrv.h"
#include "mapidlib.h"

#include "dagnew.h"
#include "dagapi.h"
#include "dagutil.h"
#include "dag_config.h"
#include "dag_component.h"

#include "dagdsm.h"

#include "mapidevices.h"
#include "flist.h"
#include "debug.h"
#include "mapi_errors.h"

#include "mapidagdrv.h"

typedef struct dag_instance {
	pthread_attr_t th_attr;
	pthread_t th_proc;
	int dagfd;
	int dagstream;
	int eventset;
	short skip;
	void *buf;
	int file;
	char *name;
	char dagname[DAGNAME_BUFSIZE];
	int id;
	mapi_offline_device_status_t *offline_status;
	mapid_hw_info_t hwinfo;
	mapidlib_instance_t mapidlib;
	u_int8_t *gpp_base;
} dag_instance_t;

#define DAGSTR "dag"

#define BUFSIZE 131072
#define MINREADSIZE 32768
#define DAGTIMEOUT 100 * 1000; /* 100ms timeout */
#define DAGPOLLINT 10 * 1000; /* 10ms poll interval */

__attribute__ ((constructor)) void init();
__attribute__ ((destructor)) void fini();

static flist_t *devlist;

/* for mapidlib errorcode */
int mapidrv_get_errno(int devid, int fd) {
	dag_instance_t *i=flist_get(devlist, devid);
	return mapid_get_errno(&i->mapidlib, fd);
}

int mapidrv_apply_function(int devid, int fd, int flags, char* function,
		mapiFunctArg *fargs) {
	dag_instance_t *i=flist_get(devlist, devid);
	int _flags = flags;

	return mapid_apply_function(&i->mapidlib, fd, function, fargs, _flags);
}

int mapidrv_add_device(const char *devname, int file, int devid,
		global_function_list_t *gflist, void *olstatus) {
	dag_instance_t *i=malloc(sizeof(dag_instance_t));

	i->name=strdup(devname);
	i->id=devid;
	i->dagfd=-1;
	i->file=file;
	i->th_proc=0;
	i->hwinfo.offline=0;
	i->hwinfo.devfd=i->dagfd;
	i->hwinfo.gflist=gflist;
	i->hwinfo.pkt_drop=0;
	i->offline_status = olstatus;
	if (devid<0)
		i->hwinfo.offline = 1;

	DEBUG_CMD(Debug_Message("Added device %d: %s", devid, devname));

	flist_append(devlist, devid, i);

	mapid_init(&i->mapidlib);

	return 0;
}

int mapidrv_delete_device(int devid) {
	dag_instance_t *i=flist_remove(devlist, devid);

	if (i!=NULL) {
		int err=0;

		if (i->th_proc && pthread_equal(i->th_proc, pthread_self())==0) {
			DEBUG_CMD(Debug_Message(
					"Calling thread != th_proc (%lu != %lu), cancelling",
					i->th_proc, pthread_self()));
			fflush(stdout);

			if ((err=pthread_cancel(i->th_proc))!=0) {
				if (!(i->hwinfo.offline==1 && err==ESRCH)) {
					DEBUG_CMD(Debug_Message(
							"WARNING: Could not cancel thread for devid %d (%s)",
							devid, strerror(err)));
					fflush(stdout);
				}
			}
		}

		if (i->hwinfo.offline==0) {
			if (i->dagfd >= 0) {

				dag_adapterinfo_t *di = i->hwinfo.adapterinfo;

				if (di != NULL) {
					if (di->card != NULL)
						dag_config_dispose(di->card); /* Freeing of the card */

					free(i->hwinfo.adapterinfo);
				}

				if (dag_stop_stream(i->dagfd, i->dagstream) < 0)
					dagutil_panic("dag_stop_stream %s:%u: %s\n", i->dagname,
							i->dagstream, strerror(errno));

				if (dag_detach_stream(i->dagfd, i->dagstream) < 0)
					dagutil_panic("dag_detach_stream %s:%u: %s\n", i->dagname,
							i->dagstream, strerror(errno));

				if (dag_close(i->dagfd) < 0)
					dagutil_panic("dag_close %s:%u: %s\n", i->dagname,
							i->dagstream, strerror(errno));

				DEBUG_CMD(Debug_Message("Closed dag device"));
			}
		} else {
			if (i->file) {
				close(i->file);
				DEBUG_CMD(Debug_Message("Closed file"));
			}
		}

		mapid_destroy(&i->mapidlib);
		free(i->name);
		if (i->offline_status != NULL)
			*(i->offline_status) = DEVICE_DELETED;
		free(i);
	}

	return 0;
}

static unsigned process_pkts(void *buf, unsigned len, dag_instance_t *i) {
	unsigned c = 0;
	unsigned rlen = 0;
	dag_record_t *rec;
	unsigned char *packet;
	mapid_pkthdr_t mhdr;

	if (len<sizeof(dag_record_t))
		return len;

	rec = (dag_record_t *) buf;
	rlen = ntohs(rec->rlen);

	// while (c < len)
	while (c + rlen <= len && rlen != 0) {
		char *p = buf;
		buf = p + rlen;
		c += rlen;
		if (rec->flags.trunc) {
			DEBUG_CMD(Debug_Message("WARNING: buffer overflow"));
		}

		packet=(unsigned char*)(&rec->rec)+i->skip;
		mhdr.caplen=ntohs(rec->rlen)-dag_record_size-i->skip;
		mhdr.wlen=ntohs(rec->wlen);
		mhdr.ts=rec->ts;
		mhdr.ifindex=rec->flags.iface;

		mapid_process_pkt(&i->mapidlib, (unsigned char*)rec, packet, &mhdr);

		if (c+sizeof(dag_record_t)>len)
			break;

		rec = (dag_record_t *) buf;
		rlen = ntohs(rec->rlen);
		i->hwinfo.pkts++;
	}

	//mapid_delete_flows(&i->mapidlib);

	return len - c;

}

static void mapidrv_offline_proc_loop(void *arg) {
	int devid = *(int *)arg; 
	char buf[BUFSIZE];
	char *b=buf;
	dag_record_t *rec;
	int left=0, c;
	dag_instance_t *i=flist_get(devlist, devid);
	int err;

	*(i->offline_status) = DEVICE_READING;

	if ((err=pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL)) != 0) {
		DEBUG_CMD(Debug_Message("ERROR: pthread_setcanceltype failed (%s)",
				strerror(err)));
		return;
	}

	if ((err=pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) != 0) {
		DEBUG_CMD(Debug_Message("ERROR: pthread_setcancelstate (%s) failed",
				strerror(err)));
		return;
	}

	//Read first record to determine link type
	c=read(i->file, b, BUFSIZE);
	if (c<1) {
		DEBUG_CMD(Debug_Message("ERROR: reading first DAG record from file"));
		return;
	}
	rec = (dag_record_t *) b;
	switch (rec->type) {
	case TYPE_HDLC_POS:
	case TYPE_DSM_COLOR_HDLC_POS:
		i->hwinfo.link_type=DLT_CHDLC;
		i->skip=0;
		break;
	case TYPE_ETH:
	case TYPE_DSM_COLOR_ETH:
		i->hwinfo.link_type=DLT_EN10MB;
		i->skip=2;
		break;
	default:
		DEBUG_CMD(Debug_Message("ERROR: Unsupported file format (%u)",rec->type));
		return;
	}

	lseek(i->file, 0, SEEK_SET);

	c=read(i->file, b, BUFSIZE);
	while (c>0) {
		left=process_pkts(buf, c+left, i);
		//Copy last bytes to beginning of buffer
		memcpy(buf, b+c-left, left);
		b=buf+left;

		c=read(i->file, b, BUFSIZE-left);
	}

	mapid_finished(&i->mapidlib);
	DEBUG_CMD(Debug_Message("Finished reading file, pkts: %llu", i->hwinfo.pkts));
	*(i->offline_status) = DEVICE_FINISHED;
}

static void mapidrv_proc_loop(void *arg) {
	int devid = *(int *)arg; 
	uint8_t *bottom= NULL;
	uint8_t *top= NULL;

	uint64_t diff;
	dag_instance_t *i=flist_get(devlist, devid);
	int err;
	struct timeval maxwait;
	struct timeval poll;
	//  int dag_ports;

	if ((err=pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL)) != 0) {
		DEBUG_CMD(Debug_Message("ERROR: pthread_setcanceltype failed (%s)",
				strerror(err)));
		return;
	}

	if ((err=pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) != 0) {
		DEBUG_CMD(Debug_Message("ERROR: pthread_setcancelstate (%s) failed",
				strerror(err)));
		return;
	}

	timerclear(&maxwait);
	maxwait.tv_usec = DAGTIMEOUT;
	timerclear(&poll);
	poll.tv_usec = DAGPOLLINT;

	dag_set_stream_poll(i->dagfd, i->dagstream, MINREADSIZE, &maxwait, &poll);
	//  dag_ports = (*((u_int32_t *)(i->gpp_base+0x00)) >> 6) & 0x03;

	while (1) {
		top=dag_advance_stream(i->dagfd, i->dagstream, &bottom);

		diff = top - bottom;
		bottom = top - process_pkts(bottom, diff, i);

		/* Measure packet loss from DAG device */
		if (i->gpp_base) {
			if (*((u_int32_t *)(i->gpp_base+0x04)) == 0xffffffff) {
				i->hwinfo.pkt_drop = *((volatile u_int32_t *)(i->gpp_base
						+ (i->dagstream+1)*0x20 + 0x04));
			} else {
				i->hwinfo.pkt_drop = *((volatile u_int32_t *)(i->gpp_base
						+0x0024));
			}
		}

	}
}

int mapidrv_read_results(int devid, int fd, int fid, mapid_result_t** result) {
	dag_instance_t *i=flist_get(devlist, devid);
	return mapid_read_results(&i->mapidlib, fd, fid, result);
}

mapid_funct_info_t* mapidrv_get_flow_functions(int devid, int fd) {
	dag_instance_t *i=flist_get(devlist, devid);
	return mapid_get_flow_functions(&i->mapidlib, fd);
}

int mapidrv_get_flow_info(int devid, int fd, mapi_flow_info_t *info) {
	dag_instance_t *i=flist_get(devlist, devid);
	return mapid_get_flow_info(&i->mapidlib, fd, info);
}

int mapidrv_create_flow(int devid, int fd, char **devtype) {
	volatile uint8_t *dagiom;
	volatile daggpp_t *gpp;
	dag_instance_t *i;
	unsigned slen=0;
	dag_reg_t *regs;
	uint32_t regn, gpp_base;
	dag_reg_t result[DAG_REG_MAX_ENTRIES];
	struct timeval maxwait;
	struct timeval poll;

	if (devid<0) {
		dag_instance_t *inst=flist_get(devlist, devid);

		*devtype=MAPI_DEVICE_DAG;
		inst->hwinfo.offline=1;

		inst->hwinfo.cap_length=1500;
		inst->hwinfo.devtype=MAPI_DEVICE_DAG;
		inst->hwinfo.devid=inst->id;
		inst->hwinfo.pkts=0;

		DEBUG_CMD(Debug_Message("Reading from trace file: %s", inst->name));

		return mapid_add_flow(&inst->mapidlib, fd, &inst->hwinfo, NULL);
	}

	i=flist_get(devlist, devid);

	i->hwinfo.offline=0;

	*devtype=MAPI_DEVICE_DAG;

	//Open device if it is not already open
	if (i->dagfd < 0) {
		dagutil_set_progname("MAPId");

		if (-1 == dag_parse_name(i->name, i->dagname, DAGNAME_BUFSIZE,
				&i->dagstream)) {
			dagutil_panic("dag_parse_name(%s): %s\n", optarg, strerror(errno));
		}

		if ((i->dagfd = dag_open(i->name)) < 0) {
			DEBUG_CMD(Debug_Message("ERROR: dag_open %s: %s", i->name,
					strerror(errno)));
			return DAGDRV_OPEN_ERR;
		}

		i->hwinfo.devfd=i->dagfd;

		if (dag_attach_stream(i->dagfd, i->dagstream, 0, 0) < 0)
			dagutil_panic("dag_attach_stream %s:%u: %s\n", i->dagname,
					i->dagstream, strerror(errno));

		if (dag_start_stream(i->dagfd, i->dagstream) < 0)
			dagutil_panic("dag_start_stream %s:%u: %s\n", i->dagname,
					i->dagstream, strerror(errno));

		i->hwinfo.cap_length=0;

		timerclear(&maxwait);
		maxwait.tv_usec = 100 * 1000; /* 100ms timeout */
		timerclear(&poll);
		poll.tv_usec = 10 * 1000; /* 10ms poll interval */

		/* 32kB minimum data to return */
		dag_set_stream_poll(i->dagfd, i->dagstream, 32*ONE_KIBI, &maxwait,
				&poll);

		regs = dag_regs(i->dagfd);
		regn = 0;
		if ((dag_reg_table_find(regs, 0, DAG_REG_GPP, result, &regn))
				|| (!regn))
			gpp_base = 0;
		else
			gpp_base = DAG_REG_ADDR(*result);

		if (gpp_base) {
			/* memory mapped area */
			dagiom = dag_iom(i->dagfd);
			if (((*(volatile uint32_t *)dagiom >> 16) & 0xff) != 0x03) {
				gpp = (daggpp_t *) (dagiom + gpp_base); /* WARNING: race */
				slen = gpp->snaplen;
				i->gpp_base = (u_int8_t*) gpp;
			}
		} else {
			i->gpp_base = NULL;
		}

		i->hwinfo.cap_length=slen;

		if (i->hwinfo.cap_length==0) {
			DEBUG_CMD(Debug_Message("WARNING: Could not get info hardware-info, using default = 1500"));
			i->hwinfo.cap_length=1500;
		}

		switch (dag_linktype(i->dagfd)) {
		default:
		case TYPE_ETH:
		case TYPE_COLOR_ETH:
		case TYPE_DSM_COLOR_ETH:
			i->hwinfo.link_type=DLT_EN10MB;
			i->skip=2;
			break;

		case TYPE_ATM:
			i->hwinfo.link_type=DLT_ATM_RFC1483;
			i->skip=4;
			break;

			/* can be both DLT_CHDLC and DLT_PPP_SERIAL?? */
		case TYPE_HDLC_POS:
			i->hwinfo.link_type=DLT_CHDLC;
			i->skip=0;
			break;
		}

		DEBUG_CMD(Debug_Message("From dag HW: cap_length=%u linktype=%u",
				i->hwinfo.cap_length, i->hwinfo.link_type));
		//i->hwinfo.devtype=MAPI_DEVICE_DAG;
		i->hwinfo.devid=i->id;
		i->hwinfo.pkts=0;

		/* Check for DSM support */
		switch (dagdsm_is_dsm_supported(i->dagfd)) {
			case 1:
				i->hwinfo.devtype=MAPI_DEVICE_DAG_DSM;
				*devtype=MAPI_DEVICE_DAG_DSM;
				DEBUG_CMD(Debug_Message("DAG: Data Stream Management (DSM) supported for BPF_FILTER function."));
				break;
			case 0:
				i->hwinfo.devtype=MAPI_DEVICE_DAG;
				DEBUG_CMD(Debug_Message("DAG: Data Stream Management (DSM) unavailable, wrong firmware loaded."));
				break;
			default:
				i->hwinfo.devtype=MAPI_DEVICE_DAG;
				DEBUG_CMD(Debug_Message("DAG: Data Stream Management (DSM) unavailable, error calling dagdsm_is_dsm_supported(), code: %d",
						dagdsm_get_last_error()));
		}

		//Start processing thread
		if (pthread_attr_init(&i->th_attr) != 0) {
			DEBUG_CMD(Debug_Message("ERROR: pthread_attr_init failed"));
			return DAGDRV_PTHR_ERR;
		}

		if (pthread_create(&i->th_proc, &i->th_attr,
				(void *) mapidrv_proc_loop, (void *) &(i->id)) != 0) {
			DEBUG_CMD(Debug_Message("ERROR: pthread_create failed"));
			return DAGDRV_PTHR_ERR;
		}

		/* The block recognizes the components for measuring packet and frames
		 * counts. Passes the prepared descriptors via adapterinfo.
		 */
		{
			dag_adapterinfo_t *di = malloc(sizeof(dag_adapterinfo_t));
			dag_component_t root;

			di->name = i->name;
			di->dagfd = i->dagfd;
			di->portcnt = 0;

			/* Gets a reference to the card, its root component and
			 * the number of ports on the card.
			 */
			di->card = dag_config_init(i->name);
			if (di->card != NULL) {
				root = dag_config_get_root_component(di->card);
				if (root != NULL) {
					di->portcnt = dag_component_get_subcomponent_count_of_type(
							root, kComponentPort);
					/* We demand sane port range. */
					if ((di->portcnt < 1) || (di->portcnt > 0xFFFF))
						di->portcnt = 0;

				}
			}

			i->hwinfo.adapterinfo = di;
		}
	}
	return mapid_add_flow(&i->mapidlib, fd, &i->hwinfo, NULL);
}

int mapidrv_connect(int devid, int fd) {
	int ret;
	dag_instance_t *i=flist_get(devlist, devid);
	if (i==NULL)
		return -1;

	ret=mapid_connect(&i->mapidlib, fd);

	if (i->hwinfo.offline==4) {
		if (pthread_attr_init(&i->th_attr) != 0) {
			DEBUG_CMD(Debug_Message("ERROR: pthread_attr_init failed"));
			return NICDRV_PTHR_ERR;
		}
		if (pthread_create(&i->th_proc, &i->th_attr,
				(void *) mapidrv_offline_proc_loop, (void *) &(i->id)) != 0) {
			DEBUG_CMD(Debug_Message("ERROR: pthread_create failed"));
			return NICDRV_PTHR_ERR;
		}
	}
	return ret;
}

int mapidrv_start_offline_device(int devid) {
	dag_instance_t *i = flist_get(devlist, devid);

	if (i->hwinfo.offline==1) {
		if (pthread_attr_init(&i->th_attr) != 0) {
			DEBUG_CMD(Debug_Message("ERROR: pthread_attr_init failed"));
			return DAGDRV_PTHR_ERR;
		}
		if (pthread_create(&i->th_proc, &i->th_attr,
				(void *) mapidrv_offline_proc_loop, (void *) &(i->id)) != 0) {
			DEBUG_CMD(Debug_Message("ERROR: pthread_create failed"));
			return DAGDRV_PTHR_ERR;
		}
	}
	return 0;
}

int mapidrv_close_flow(int devid, int fd) {
	dag_instance_t *i=flist_get(devlist, devid);
	int rc = mapid_close_flow(&i->mapidlib, fd);

	return rc;
}

int mapidrv_load_library(MAPI_UNUSED int devid, char* lib) {
	return mapid_load_library(lib);
}

__attribute__ ((constructor))
void init() {
	devlist=malloc(sizeof(flist_t));
	flist_init(devlist);
	printf("DAG driver loaded [%s:%d]\n",__FILE__ ,__LINE__);
}

__attribute__ ((destructor))
void fini() {
	free(devlist);
	printf("DAG driver unloaded [%s:%d]\n",__FILE__ ,__LINE__);
}

int mapidrv_stats(int devid, char **devtype, struct mapi_stat *stats) {
	dag_instance_t *i=flist_get(devlist, devid);

	*devtype=MAPI_DEVICE_DAG;

	if (i!=NULL) {
		stats->ps_recv=i->hwinfo.pkts;
		stats->ps_drop=i->hwinfo.pkt_drop;
		stats->ps_ifdrop=0;
		return 0;
	}
	return MAPI_STATS_ERROR;
}

