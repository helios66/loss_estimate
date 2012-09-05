#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "debug.h"
#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapi_errors.h"
#include "mapid.h"

#include "dagapi.h"
#include "dag_config.h"
#include "dagdsm.h"

#include "mapidagdrv.h"
#include "parseconf.h"
#include "printfstring.h"
#include "bpfcompiler/bpfcompiler.h"

#define DSM_FILTER_COUNT 7	/* DSM DAG have 8 filters minus one swap filter (why?) */

struct bpffilter_internal {
  unsigned char filtermask;
};

int dagdsm_build_bpffilter(int only_check, char *new_filter_string, mapidflib_function_instance_t* instance);
int get_fid_from_instance(mapidflib_function_instance_t *instance);

static int bpffilter_instance(mapidflib_function_instance_t *instance,
                              int fd,
                              MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{
  mapiFunctArg* fargs=instance->args;
  char *str = getargstr(&fargs);
  int rc;
  conf_category_t *conf;

  /* Checking Arguments */
  if(str == NULL)
    return MFUNCT_INVALID_ARGUMENT_1;

  if(strlen(str) < 1)  // could also force a maximum length for the filter expression
    return MFUNCT_INVALID_ARGUMENT_1;

  /* Check dsm_loader binary */
  if ((conf = pc_load(CONFDIR "/" CONF_FILE)) != NULL) {
    conf_category_entry_t *cat = pc_get_category(conf, "dag");
    char *binpath = cat ? pc_get_param(cat, "dsm_loader_bin") : NULL;

    if (!binpath || !*binpath || (access(binpath, X_OK) != 0)) {
      DEBUG_CMD(Debug_Message("DAG: Data Stream Management (DSM) disabled due to bad setting of parameter dsm_loader_bin in %s",
          CONF_FILE));
      pc_close(conf);
      return MFUNCT_COULD_NOT_APPLY_FUNCT;
    }

    pc_close(conf);
  }
  else {
    DEBUG_CMD(Debug_Message("Error opening configuration file %s, disabling DAG DSM", CONF_FILE));
    return MFUNCT_COULD_NOT_APPLY_FUNCT;
  }

  if ((rc =dagdsm_build_bpffilter(fd, str, instance)) != 0)
    return rc;

  return 0;
}

static int bpffilter_init(mapidflib_function_instance_t *instance,
                          MAPI_UNUSED int fd)
//Initializes the function
{
  char* str;
  mapiFunctArg* fargs;
  int rc;

  fargs=instance->args;
  str =(char*) getargstr(&fargs);

  instance->internal_data = malloc(sizeof(struct bpffilter_internal));

  if ((rc = dagdsm_build_bpffilter(0, str, instance)) != 0)
    return rc;

  return 0;
}

static int bpffilter_process(mapidflib_function_instance_t* instance,
                             unsigned char* dev_pkt,
                             MAPI_UNUSED unsigned char* link_pkt,
                             MAPI_UNUSED mapid_pkthdr_t* pkt_head)
{
  /* Match function filtermask against ERF filter bits. If one or more of the filters
   * match pass the packet on, and if no filters match drop it.
   */
  unsigned char packetfilters = (dev_pkt[12] << 2) | (dev_pkt[13] >> 6);
  unsigned char filtermask = ((struct bpffilter_internal *)instance->internal_data)->filtermask;

  /*printf("ERF filters = 0x%02x, filtermask = 0x%02x -> %s\n", packetfilters, filtermask,
      ((packetfilters & filtermask) != 0) ? "PASSED" : "DROP" );*/

  if ((packetfilters & filtermask) != 0)
    return 1; //send packet on
  else
    return 0; //drop packet
}

static int bpffilter_cleanup(mapidflib_function_instance_t *instance) {
  if(instance->internal_data != NULL){
    free(instance->internal_data);
  }
  if (dagdsm_build_bpffilter(0, NULL, instance) != 0) {
    DEBUG_CMD(Debug_Message("Could not rebuild filters after function finished."));
  }
  return 0;
}

static mapidflib_function_def_t finfo={
  "",			//libname
  "BPF_FILTER",		//name
  "DAG specific BPF filter, DSM version.\nParameters:\n\tBPF filter: char*", //descr
  "s",			//argdescr
  MAPI_DEVICE_DAG_DSM,	//devtype
  MAPIRES_NONE,		//Method for returning results
  0,			//shm size
  0,			//modifies_pkts
  1,			//filters_pkts
  MAPIOPT_NONE,		//global optimization method
  bpffilter_instance,	//instance
  bpffilter_init,	//init
  bpffilter_process,	//process
  NULL,			//get_result,
  NULL,			//reset
  bpffilter_cleanup,	//cleanup
  NULL,			//client_init
  NULL,			//client_read_result
  NULL			//client_cleanup
};

mapidflib_function_def_t* bpffilter_get_funct_info();

mapidflib_function_def_t* bpffilter_get_funct_info() {
  return &finfo;
};

/* 1) Compiles and builds the DSM filter for all dagflib:BPF_FILTER instances.
 * 2) When only_check == 0, the subprocess dsm_loader is called to
 *    activate the filter.
 *    When only_check != 0, the read-only run is conducted & the new
 *    dagflib:BPF_FILTER instance's fitness is detected and returned. 
 * 3) If called with only_check == 0 and new_filter_string == NULL the live flows
 *    are recompiled and uploaded to card. Useful when closing a BPF_FILTER flow.
 */
int dagdsm_build_bpffilter(int only_check, char *new_filter_string, mapidflib_function_instance_t* instance) {
  dagdsm_bpf_filter_t *filter = NULL;
  flist_node_t *flownode, *funcnode;
  mapid_flow_info_t *fi;
  flist_t *functions;
  int filter_count = 0, index=1, fid, rc_err = 0;
  char errbuf[BPF_ERRBUF_SIZE];
  dag_adapterinfo_t *di = instance->hwinfo->adapterinfo;

  /* find the fid of this instance, so that we dont build filters instanced after this one. */
  fid = get_fid_from_instance(instance);

  /* iterate for each function in each flow. */
  while(__sync_lock_test_and_set(&(instance->hwinfo->gflist->lock),1));
  
  for (flownode=flist_head(instance->hwinfo->gflist->fflist); flownode && !rc_err; flownode=flist_next(flownode)) {
    fi = flist_data(flownode);

    if (fi->status == FLOW_CLOSED) continue;   /* skip flows marked for deletion */

    if (NULL != (functions=fi->flist)) {
      for (funcnode=flist_head(functions); funcnode; funcnode=flist_next(funcnode)) {
        mapidflib_function_t *flibf = flist_data(funcnode);
        mapidflib_function_instance_t *funct=flibf->instance;

        if (fid > 0 && flibf->fid >= fid) {
          continue; /* skip functions applied after this one, so we dont build filters multiple times */
        }

        if (!strcmp(funct->def->devtype, MAPI_DEVICE_DAG_DSM)) {
          /*printf("\tFOUND DAGFUNC %s fid=%d %p  mask %x\n",
              funct->def->name, flibf->fid, funct,
		(funct->internal_data != NULL) ?((struct bpffilter_internal *)funct->internal_data)->filtermask : 0);*/

          if (!strcmp(funct->def->name, "BPF_FILTER")) {
            mapiFunctArg *fargs=funct->args;
            char *bpf_filter_string = getargstr(&fargs);   /* get the string BPF expr */
            unsigned char filtermask;

            if ((filter = dagdsm_bpf_compile(filter, bpf_filter_string, index++, errbuf)) == NULL) {
              DEBUG_CMD(Debug_Message("ERROR: dagdsm_build_bpffilter: Strange! Compilation error in previous BPF expression '%s': %s",
	          bpf_filter_string, errbuf));
              rc_err =  MFUNCT_COULD_NOT_APPLY_FUNCT;
              break;
            }

            if(!only_check) {
              /* We determine, what DAG hardware filters were used by the last
               * compiled expression. */
              filtermask = dagdsm_bpf_get_last_usage_mask(filter);

              /* If this function has been initialized, update its filtermask */
              if (funct->internal_data != NULL) { 
                /*DEBUG_CMD(Debug_Message("Initializing function %s\tfid=%d, mask=0x%02x", \
                          funct->def->name, flibf->fid, filtermask & ~0x80000000));*/

                /*printf("\tSETTING NEW MASK FOR FUNC %s %p: %x <- %x (new)\n",
                    funct->def->name, funct, ((struct bpffilter_internal *)funct->internal_data)->filtermask, filtermask);*/

                ((struct bpffilter_internal *)funct->internal_data)->filtermask = filtermask;
              }
            }
          }
        }
      }
    }
  }
  instance->hwinfo->gflist->lock = 0;

  /* quit now if we've stumbled upon an error */
  if (rc_err) {
    if (filter != NULL) {
      dagdsm_bpf_free(filter);
    }
    return rc_err;
  }

  //Test filter string
  if (new_filter_string != NULL) {
    filter = dagdsm_bpf_compile(filter, new_filter_string, index, errbuf);
    if (filter == NULL) {
      DEBUG_CMD(Debug_Message("ERROR: dagdsm_build_bpffilter: Compilation error in BPF expression '%s': %s",
          new_filter_string, errbuf));
      return MFUNCT_COULD_NOT_APPLY_FUNCT;
    }
  }

  //Test if hardware can fit all the filters
  filter_count = dagdsm_bpf_get_filter_count(filter);
  if (filter_count > DSM_FILTER_COUNT) {
    DEBUG_CMD(Debug_Message("dagdsm_build_bpffilter: BPF expression of %d filters would not fit to the hardware having only %d filters",
                                               filter_count, DSM_FILTER_COUNT));
    if (filter != NULL) {
      dagdsm_bpf_free(filter);
    }
    return MFUNCT_COULD_NOT_APPLY_FUNCT; /* too many hardware filters */
  }

  if(!only_check && new_filter_string != NULL) {
    /* We determine, what DAG hardware filters were used by the last compiled expression. */
    unsigned char filtermask = dagdsm_bpf_get_last_usage_mask(filter);

    /*DEBUG_CMD(Debug_Message("Initializing function BPF_FILTER\tfid=%d, mask=0x%02x", \
        fid, filtermask & ~0x80000000));
    printf("\tSETTING NEW MASK FOR FUNC BPF_FILTER: %x <- %x (new)\n",
        ((struct bpffilter_internal *)instance->internal_data)->filtermask, filtermask);*/

    /* update function instance's filtermask */
   ((struct bpffilter_internal *)instance->internal_data)->filtermask = filtermask;
 }

  //Make changes to the DSM config and apply
  if (!rc_err && !only_check) {
    if (filter_count > 0) {
      char *reason = "unknown", *binpath = NULL, *xml_filter;
      char *command, tmpfn[] = "/tmp/mapid.dagdsm.temp.xml.XXXXXX";
      conf_category_t *conf;

      rc_err = MFUNCT_COULD_NOT_APPLY_FUNCT;

      /* First we check whether we can execute the dsm_loader binary at all. */
      if ((conf = pc_load(CONFDIR "/" CONF_FILE)) != NULL) {
        conf_category_entry_t *cat = pc_get_category(conf, "dag");
        int remove_xml = 1;

        if (cat) {
          char *disable_dsm_xml_remove = pc_get_param(cat, "disable_dsm_xml_remove");
          binpath = pc_get_param(cat, "dsm_loader_bin");

          if (disable_dsm_xml_remove && *disable_dsm_xml_remove && !strcmp(disable_dsm_xml_remove, "1")) {
            remove_xml = 0;
          }
        }

        if (binpath && *binpath && (access(binpath, X_OK) == 0)) {

          if ((xml_filter = dagdsm_bpf_xprintf(filter, 1, di->portcnt, errbuf)) != NULL) {
            int tmpfd;
            if ((tmpfd = mkstemp(tmpfn)) != -1) {
              if ((command = printf_string("%s -d %s -f %s >/dev/null 2>/dev/null", binpath, di->name, tmpfn)) != NULL) {
                int fl = strlen(xml_filter);
                fl -= write(tmpfd, xml_filter, fl);
                close(tmpfd);
                if (fl == 0) {
                  int rc;

                  DEBUG_CMD(Debug_Message("dagdsm_build_bpffilter: Executing `%s'", command));
                  rc = system(command);
                  if ((rc != -1) && WIFEXITED(rc) && (WEXITSTATUS(rc) == 0)) {
                    rc_err = 0;     /* whoaaa... */
                    DEBUG_CMD(Debug_Message("DAG: DSM filters downloaded to the card successfully, occupied filters: %d", filter_count));

                  } else reason = "problem executing the command dsm_loader_bin";
                } else reason = "problem writing to temporary file";
                free(command);
              } else reason = "problem formatting the command";
              if (remove_xml && (rc_err == 0))
                unlink(tmpfn);
            } else reason = "could not create a temporary file in /tmp";
            free(xml_filter);
          } else reason = errbuf;
        } else reason = "missing or invalid path dsm_loader_bin (category [dag]) in the configuration file";
        pc_close(conf);
      } else reason = "problem opening the mapid configuration file";

      if (rc_err) {
        DEBUG_CMD(Debug_Message("ERROR: calling dsm_loader_bin program. "
          "CAPTURING HARDWARE IN UNKNOWN STATE! XML configuration should be in %s. "
          "Original reason: %s", tmpfn, reason));
      }

    } else {    /* filter_count <= 0 */
      DEBUG_CMD(Debug_Message("dagdsm_build_bpffilter: No hardware filters requested, bypassing the DSM (rc=%d)",
          dagdsm_bypass_dsm (di->dagfd, 1)));
    }
  }

  if (filter != NULL) {
    dagdsm_bpf_free(filter);
  }

  return rc_err;
}

int get_fid_from_instance(mapidflib_function_instance_t *instance) {
  int fid = -1;
  flist_node_t *flownode, *funcnode;
  mapid_flow_info_t *fi;
  flist_t *functions;
 
  while(__sync_lock_test_and_set(&(instance->hwinfo->gflist->lock),1));
  for (flownode=flist_head(instance->hwinfo->gflist->fflist); flownode; flownode=flist_next(flownode)) {
    fi = flist_data(flownode);

    if (fi->status == FLOW_CLOSED) continue;   /* skip flows marked for deletion */

    if (NULL != (functions=fi->flist)) {

      for (funcnode=flist_head(functions); funcnode; funcnode=flist_next(funcnode)) {
        mapidflib_function_t *flibf = flist_data(funcnode);
        mapidflib_function_instance_t *funct=flibf->instance;

        if (funct == instance) {
          fid = flibf->fid;
          break;
        }
      }
    }
  }
  instance->hwinfo->gflist->lock = 0;
  return fid;
}
