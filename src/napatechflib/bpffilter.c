#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>

#include "mapidflib.h"
#include "mapidlib.h"
#include "mapidevices.h"
#include "mapid.h"
#include "fhelp.h"
#include "mapi_errors.h"
#include "debug.h"
#include "mapinapatechdrv.h"

#define bool_t unsigned int
#include "packetclassificationstructure.h"
#include "packetdescriptor.h"
#include "extendeddescriptor05.h"
#include "NTCI_packetclassification.h"

#define BPF_FILTER "BPF_FILTER"

/*struct bpf_filter {
  struct bpf_program compiled;
};*/

struct bpf_internal_data {
  handle_t napatechhandle;
  char *expression;
  unsigned int filter_id; // filter id from driver
  unsigned long long group_index; // 64bit colors from driver
};

static int bpf_instance(mapidflib_function_instance_t *instance,
			MAPI_UNUSED int fd,
			MAPI_UNUSED mapidflib_flow_mod_t *flow_mod)
{

  mapiFunctArg* fargs=instance->args;
  char *str = getargstr(&fargs);
  
  if (instance->hwinfo->offline != 0) // Cant use packet classification on offline streams
    return -1; // FIXME: errorcode
  
  /* 
   *	Checking Arguments
   */
  if(str == NULL)
    return MFUNCT_INVALID_ARGUMENT_1;

  if(strlen(str) < 1)  // could also force a maximum length for the filter expression
    return MFUNCT_INVALID_ARGUMENT_1;

  /*
   *	Dummy BPF filter compilation in order to check filter is OK.
   */
 /* if((pcap = pcap_open_dead(instance->hwinfo->link_type, instance->hwinfo->cap_length)) == NULL){
    DEBUG_CMD(Debug_Message("pcap_open_dead failed"));
    return PCAP_OPEN_DEAD_ERR;
  }
  
  temp = malloc(sizeof(struct bpf_filter));

  if(pcap_compile(pcap, ((struct bpf_program*)&((struct bpf_filter *)temp)->compiled), str, 1, 0)) {
    DEBUG_CMD(Debug_Message("bpf compilation error: %s str: \"%s\"", pcap_geterr(pcap), str));
    free(temp);
    return PCAP_BPF_ERR;
  }

  pcap_close(pcap);
  pcap_freecode((struct bpf_program *)&((struct bpf_filter *)temp)->compiled);
  free(temp);
*/


  /*
    NOTE: The filter should really be applied in init() and only checked for validity here,
    but as there is no way to test-compile the expression and check for resources
    it's done here.
  */
  int result;
  PassFilter_t command;
  command.WriteHW = TRUE;
  sprintf(command.achFilterString, str); //"Capture[Priority=0;Feed=0]=ALL");

  if((result = NTCI_PacketClassification(((napa_nt_adapterinfo_t *)instance->hwinfo->adapterinfo)->napatechhandle,
                                         STID_PASS_FILTER,
                                         &command)) != NTCI_ERRCODE_SUCCESS) {
                 printf("----got errorcode %d\n",result);
    FilterError_t error;
    result = NTCI_PacketClassification(((napa_nt_adapterinfo_t *)instance->hwinfo->adapterinfo)->napatechhandle,
                                       STID_GET_FILTER_ERROR,
                                       &error);
    DEBUG_CMD(Debug_Message("%s",error.achFilterError1)); // stderr
    DEBUG_CMD(Debug_Message("%s",error.achFilterError2)); // stderr
    DEBUG_CMD(Debug_Message("%s",error.achFilterError3)); // stderr

    return MFUNCT_COULD_NOT_APPLY_FUNCT; // FIXME: errorcode
  }

  instance->internal_data = malloc(sizeof(struct bpf_internal_data));
  struct bpf_internal_data *idata = (struct bpf_internal_data *)instance->internal_data;
  idata->napatechhandle = ((napa_nt_adapterinfo_t *)instance->hwinfo->adapterinfo)->napatechhandle;
  idata->expression = strdup(command.achFilterString);
  idata->filter_id = command.ReturnData.u.FilterIndex.FilterId;
  idata->group_index = command.ReturnData.u.FilterIndex.u.GroupIndex;

  DEBUG_CMD(Debug_Message("BPF_NTPL: %s\n\tFilterId: %u GroupIndex: 0x%lx", idata->expression, idata->filter_id, idata->group_index));

  return 0;
}

static int bpf_init(mapidflib_function_instance_t *instance,
		    MAPI_UNUSED int fd)
//Initializes the function
{
  char* str;
  mapiFunctArg* fargs;
  int result;

  fargs=instance->args;
  str =(char*) getargstr(&fargs);

  /* Should really apply fitlers here instead */

  return 0;
}

static int bpf_process(mapidflib_function_instance_t *instance,
		       unsigned char* dev_pkt,
		       MAPI_UNUSED unsigned char* link_pkt,
		       MAPI_UNUSED mapid_pkthdr_t* pkt_head)
{
  //return bpf_filter(((struct bpf_program)((struct bpf_filter*)instance->internal_data)->compiled).bf_insns, (unsigned char *)link_pkt,pkt_head->caplen,pkt_head->wlen);

  // FIXME: PacketDescriptorType2_t is for X family cards
  //PacketDescriptorType2_t *descriptor = (PacketDescriptorType2_t *)dev_pkt;

  PacketDescriptorNtSeriesType1_t *descriptor = (PacketDescriptorNtSeriesType1_t *) dev_pkt;

  // Extended descriptor needed to find packet color
  if (descriptor->extensionFormat == EXTENDED_DESCRIPTOR_05_TYPE) {
    PacketExtDescriptorType05_t *pExtDescr = (PacketExtDescriptorType05_t*)(((uint8_t*)descriptor) + sizeof(PacketDescriptorNtSeriesType1_t));

    // Match the packet color to filter(s)
    if (((1<<pExtDescr->color) & ((struct bpf_internal_data *)instance->internal_data)->group_index) != 0)
      return 1;
  }

  return 0;
}

static int bpf_cleanup(mapidflib_function_instance_t *instance) {

  // Clear filter
  int result;
  PassFilter_t command;
  command.WriteHW = TRUE;
  sprintf(command.achFilterString, "DeleteFilter = %u", ((struct bpf_internal_data *)instance->internal_data)->filter_id);

  // Hack to see if card is closed
  char namebuff[16];
  result = NTCI_GetDeviceName(((struct bpf_internal_data *)instance->internal_data)->napatechhandle, namebuff, 16);

  if (result == NTCI_ERRCODE_SUCCESS) {
    if((result = NTCI_PacketClassification(((struct bpf_internal_data *)instance->internal_data)->napatechhandle, //((napa_nt_adapterinfo_t *)instance->hwinfo->adapterinfo)->napatechhandle,
                                           STID_PASS_FILTER,
                                           &command)) != NTCI_ERRCODE_SUCCESS) {

      FilterError_t error;
      result = NTCI_PacketClassification(((struct bpf_internal_data *)instance->internal_data)->napatechhandle, //((napa_nt_adapterinfo_t *)instance->hwinfo->adapterinfo)->napatechhandle,
                                         STID_GET_FILTER_ERROR,
                                         &error);

      DEBUG_CMD(Debug_Message("%s",error.achFilterError1)); // stderr
      DEBUG_CMD(Debug_Message("%s",error.achFilterError2)); // stderr
      DEBUG_CMD(Debug_Message("%s",error.achFilterError3)); // stderr

      return 1; // FIXME: errorcode
    }
  }
  else {
    printf("ERROR: Card closed, cannot free filter with id %u\n", ((struct bpf_internal_data *)instance->internal_data)->filter_id);
    // TODO: delete the filter anyway, maybe re-opening the card to delete and re-close. Or maybe even calling NtplTool (dirty)
  }

  if (instance->internal_data != NULL) {
    free(((struct bpf_internal_data *)instance->internal_data)->expression);
    free(instance->internal_data);
  }

  return 0;
}

static mapidflib_function_def_t finfo={
  "", //libname
  BPF_FILTER, //name
  "Napatech NT specific BPF filter function\nParameters:\n\tBPF filter: char*", //Description
  "s", //argdescr
  MAPI_DEVICE_NAPATECH_NT, //Devoid
  MAPIRES_NONE,
  0, //shm size
  0, //modifies_pkts
  1, //filters packets
  MAPIOPT_AUTO, //Optimization
  bpf_instance,
  bpf_init,
  bpf_process,
  NULL,
  NULL,
  bpf_cleanup,
  NULL,
  NULL, 
  NULL
};

mapidflib_function_def_t* bpf_get_funct_info();

mapidflib_function_def_t* bpf_get_funct_info() {
  return &finfo;
}
