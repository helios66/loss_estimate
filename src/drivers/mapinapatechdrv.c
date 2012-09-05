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

#include "mapidevices.h"
#include "flist.h"
#include "debug.h"
#include "mapi_errors.h"
#include "mapinapatechdrv.h"

#define bool_t int

/* The NTCommonInterface.h header provides the interface definitions
 *  * for the Napatech NTCI library */
#include <NTCommonInterface.h>

/* These headers are needed when capturing traffic */
#include <packetfeedstructure.h>
#include <packetdescriptor.h>
#include <NTCI_packetfeed.h>
#include <NTCI_errorcode.h>
#include <NTCI_capabilities.h>
#include <capabilitiesstructure.h>
#include <NTCI_packetclassification.h>
#include <packetclassificationstructure.h>
#include <extendeddescriptor05.h>

typedef struct napatech_instance {
  pthread_attr_t th_attr;
  pthread_t th_proc;
  handle_t napatechhandle;
  uint32_t packetfeedhandle;
  uint32_t channelsBitmask;
  FeedBufferInformationType1_t bufferInfo;
  int eventset;
  short skip;
  void *buf;
  int file;
  char *name;
  int id;
  mapi_offline_device_status_t *offline_status;
  mapid_hw_info_t hwinfo;
  mapidlib_instance_t mapidlib;
  u_int8_t *gpp_base;
} napatech_instance_t;

__attribute__ ((constructor)) void init ();
__attribute__ ((destructor))  void fini ();

static flist_t *devlist;

/* for mapidlib errorcode */
int
mapidrv_get_errno(int devid,int fd)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_get_errno"));

  napatech_instance_t *i=flist_get(devlist,devid);
  return mapid_get_errno(&i->mapidlib,fd);
}

#ifdef WITH_AUTHENTICATION
int mapidrv_authenticate(int devid, int fd, char *vo)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_authenticate"));
	napatech_instance_t *i = flist_get(devlist, devid);
	return mapid_authenticate(&i->mapidlib, fd, vo);
}
#endif

int
mapidrv_apply_function (int devid,int fd, int flags, char* function, mapiFunctArg *fargs)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_apply_function"));

  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_apply_function; devid = %d; fd = %d; function = %s", devid, fd, function));

  napatech_instance_t *i=flist_get(devlist,devid);

  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_apply_function; &i = %x", (int)i));

  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_apply_function; &i->mapidlib = %x", (int)(&i->mapidlib)));

  int _flags = flags;

  return mapid_apply_function(&i->mapidlib, fd, function, fargs, _flags);
}

int mapidrv_add_device(const char *devname, int file,int devid, global_function_list_t *gflist,void *olstatus)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_add_device"));

  napatech_instance_t *i=malloc(sizeof(napatech_instance_t));

  i->napatechhandle = NULL;
  i->packetfeedhandle = 0;

  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_add_device; devname: %s", devname));
  i->name=strdup(devname);
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_add_device; i->name: %s", i->name));
  i->id=devid;
  // i->dagfd=-1;
  i->file=file;
  // i->th_proc=0;
  i->hwinfo.offline=0;
  i->hwinfo.devfd=i->napatechhandle;
  i->hwinfo.gflist=gflist;
  i->hwinfo.pkt_drop=0;
  i->offline_status = olstatus;
  if(devid<0)
  {
    i->hwinfo.offline = 1;
    i->hwinfo.adapterinfo = NULL;
  }
  else
  {
    i->hwinfo.adapterinfo = malloc(sizeof(napa_nt_adapterinfo_t));
  }

  DEBUG_CMD(Debug_Message("Added device %d: %s", devid, devname));

  flist_append(devlist,devid,i);
  mapid_init(&i->mapidlib);
  return 0;
}

int mapidrv_delete_device(int devid)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_delete_device"));

  napatech_instance_t *i=flist_remove(devlist,devid);

  uint32_t result;

  if (i!=NULL) {
    int err=0;

    if (i->th_proc && pthread_equal(i->th_proc, pthread_self())==0) {
      DEBUG_CMD(Debug_Message("Calling thread != th_proc (%lu != %lu), cancelling", i->th_proc, pthread_self()));
      fflush(stdout);

      if ((err=pthread_cancel(i->th_proc))!=0) {
        if (!(i->hwinfo.offline==1 && err==ESRCH)) {
          DEBUG_CMD(Debug_Message("WARNING: Could not cancel thread for devid %d (%s)", devid, strerror(err)));
          fflush(stdout);
        }
      }
    }

    if(i->napatechhandle != NULL) {
      if((result = NTCI_StopPacketFeed(i->napatechhandle, i->packetfeedhandle)) != NTCI_ERRCODE_SUCCESS) {
        DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_delete_device; Failed to stop packet feed! (%i)\n", result));
      }

      /*      if((result = NTCI_DestroyPacketFeed(i->napatechhandle, i->packetfeedhandle)) != NTCI_ERRCODE_SUCCESS) {
        DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_delete_device; Failed to destroy packet feed! (%i)\n", result));
	}*/
      NTCI_CloseCard(i->napatechhandle);
      DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_delete_device; Napatech device closed"));
      i->napatechhandle = NULL;
    }

    mapid_destroy(&i->mapidlib);
    free(i->name);
    if(i->offline_status != NULL)
      *(i->offline_status) = DEVICE_DELETED;

    if (i->hwinfo.adapterinfo != NULL) {
      ((napa_nt_adapterinfo_t *)i->hwinfo.adapterinfo)->napatechhandle = NULL;
      free(i->hwinfo.adapterinfo);
      i->hwinfo.adapterinfo = NULL;
    }

    free(i);
  }

  return 0;
}

static unsigned
// process_pkts(void *buf,unsigned len, napatech_instance_t *i)
process_pkts(BufferInformationSectionType1_t* bufferInformation, napatech_instance_t *i)
{
  /* DEBUG_CMD(Debug_Message("napatechdrv: process_pkts"));
  DEBUG_CMD(Debug_Message("napatechdrv: process_pkts; packet count: %d", bufferInformation->numDescriptorsAvailable)); */

  mapid_pkthdr_t mhdr;

  uint32_t packet = 0;
  uint8_t *frame = NULL;

  // FIXME: Should this not be PacketDescriptorNtSeriesType1_t for NT cards?
  //    The fields used are the same in both, but the rest is different. Might cause confusion later on.
  PacketDescriptorType2_t *descriptor = (PacketDescriptorType2_t *)(((uint8_t*)(i->bufferInfo.bufferBaseAddress)) + bufferInformation->sectionOffset);

  // pNetFlow->flowStat.uiTotalDropped+=bufferInformation.numDroppedFrames;

  if(descriptor->ExtensionFormat == EXTENDED_DESCRIPTOR_05_TYPE) {
    for(packet=0; packet < bufferInformation->numDescriptorsAvailable; packet++) {
      i->hwinfo.pkts++;

      PacketExtDescriptorType05_t *pExtDescr = (PacketExtDescriptorType05_t*)(((uint8_t*)descriptor) + sizeof(PacketDescriptorType2_t));

      frame = ((uint8_t*)descriptor);


      printf("timestamp: %llu\n", descriptor->Timestamp);
      mhdr.ts = ((4503599*(descriptor->Timestamp>>32))>>20)|(descriptor->Timestamp<<32) ;
      mhdr.ifindex = descriptor->Channel;
      mhdr.caplen = descriptor->StoredLength;
      mhdr.wlen = descriptor->WireLength;

			// Layer 2 type. (0:EtherII, 1:LLC, 2:SNAP, 3:Novell RAW)
			switch(pExtDescr->l2Type) {
				case 0:
					i->hwinfo.link_type = DLT_EN10MB;
					break;
				case 1:
				case 2:
				case 3:
				default:
					DEBUG_CMD(Debug_Message("WARNING: Unexpected Layer 2 type (%d) in Extended Packet Descriptor\n", pExtDescr->l2Type));
					break;
			}

      // ? TODO - modify third argument to pass test_packet_read
      mapid_process_pkt(&i->mapidlib, (unsigned char*)frame, frame + sizeof(PacketDescriptorType2_t) + (descriptor->ExtensionLength << 3), &mhdr);

      /* Avance to the next packet. */
      descriptor = (PacketDescriptorType2_t*)((uint8_t*)descriptor + descriptor->StoredLength);
    }
  } else {
    for(packet=0; packet < bufferInformation->numDescriptorsAvailable; packet++) {
      i->hwinfo.pkts++;

      frame = ((uint8_t*)descriptor);

      //Todo: temporary solution.
      mhdr.ts = ((4503599*(descriptor->Timestamp>>32))>>20)|(descriptor->Timestamp<<32) ;
      mhdr.ifindex = descriptor->Channel;
      mhdr.caplen = descriptor->StoredLength;
      mhdr.wlen = descriptor->WireLength;

      // ? TODO - modify third argument to pass test_packet_read
      mapid_process_pkt(&i->mapidlib, (unsigned char*)frame, frame + sizeof(PacketDescriptorType2_t), &mhdr);

      /* Avance to the next packet. */
      descriptor = (PacketDescriptorType2_t*)((uint8_t*)descriptor + descriptor->StoredLength);
    }
  }

  return 0;
}

static unsigned
process_pkts_offline(void *buf,unsigned len, napatech_instance_t *i)
{
  DEBUG_CMD(Debug_Message("napatechdrv: process_pkts_offline"));

  /* TODO */

  return 0;

}

static void
mapidrv_offline_proc_loop(void *arg)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_offline_proc_loop"));

  /* TODO */

}

static void
mapidrv_proc_loop (void *arg)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_proc_loop"));

  int devid = *(int *)arg;
  napatech_instance_t *i=flist_get(devlist,devid);
  int err;

  BufferRequestSampledType2_t request;
  // BufferInformationSectionType6_t bufferInformation;
  BufferInformationSectionType1_t bufferInformation;
  uint32_t result;

  request.common.waitTimeoutMS=GET_NEXT_BUFFER_INFINITE_WAIT;

  if ((err=pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL)) != 0) {
     DEBUG_CMD(Debug_Message("ERROR: pthread_setcanceltype failed (%s)",strerror(err)));
     return;
  }

  if ((err=pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)) != 0) {
     DEBUG_CMD(Debug_Message("ERROR: pthread_setcancelstate (%s) failed", strerror(err)));
     return;
  }

  while (1)
    {

    //DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_proc_loop; i->napatechhandle: %d; i->packetfeedhandle: %d", i->napatechhandle, i->packetfeedhandle));

    result = NTCI_GetNextBuffer(i->napatechhandle,
                                i->packetfeedhandle,
                                STID_BUFFER_REQUEST_SAMPLED_TYPE2,
                                &request,
                                STID_BUFFER_INFORMATION_SECTION_TYPE1,
                                &bufferInformation);

    if(result == NTCI_ERRCODE_SUCCESS) {

    i->hwinfo.pkt_drop += bufferInformation.numDroppedFrames;

    if(bufferInformation.numDescriptorsAvailable > 0) process_pkts(&bufferInformation, i);

      NTCI_ReleaseBuffer(i->napatechhandle,
                         i->packetfeedhandle,
                         STID_BUFFER_INFORMATION_SECTION_TYPE1,
                         &bufferInformation);
    } else if(result != NTCI_STATUSCODE_NO_PACKETS_AVAILABLE) {
      DEBUG_CMD(Debug_Message("Failed to get buffers. Error code %d\n", result)); //stderr
      break;
    } else {
      DEBUG_CMD(Debug_Message("%s: %s\n", "NTCI_GetNextBuffer", "NTCI_STATUSCODE_NO_PACKETS_AVAILABLE"));
    }

    }
 }


int
mapidrv_read_results (int devid,int fd, int fid, mapid_result_t** result)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_read_results"));

  napatech_instance_t *i=flist_get(devlist,devid);
  return mapid_read_results(&i->mapidlib,fd,fid,result);
}

mapid_funct_info_t* mapidrv_get_flow_functions(int devid,int fd)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_get_flow_functions"));

  napatech_instance_t *i=flist_get(devlist,devid);
  return mapid_get_flow_functions(&i->mapidlib,fd);
}

int mapidrv_get_flow_info(int devid,int fd,mapi_flow_info_t *info) {
  /* DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_get_flow_info")); */

  napatech_instance_t *i=flist_get(devlist,devid);
  return mapid_get_flow_info(&i->mapidlib,fd,info);
}

int
mapidrv_create_offline_flow (int devid, int format,int fd,char **devtype)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_create_offline_flow"));

  napatech_instance_t *i=flist_get(devlist,devid);

  /* TODO */

  return 0;
}

int
mapidrv_create_flow (int devid, int fd, char **devtype)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_create_flow"));

  napatech_instance_t *i;

  uint32_t result=0;
  uint32_t feedPriorities[] = { 1 };
  FeedConfigSampledType2_t feedConfig;
  // BufferInformationSectionType6_t bufferInformation;
  // FeedBufferInformationType1_t bufferInfo;
  // BufferRequestSampledType2_t request;
  CardHardwareCapabilitiesType1_t cardCapabilities;
  uint32_t channelsBitmask=0;
  CardHardwareVersionCapabilitiesType3_t data3;

  if(devid < 0)
    {
      napatech_instance_t *inst=flist_get(devlist,devid);

      *devtype=MAPI_DEVICE_NAPATECH_NT;
      inst->hwinfo.offline=1;

      inst->hwinfo.cap_length=1500;
			inst->hwinfo.link_type=DLT_EN10MB;
      inst->hwinfo.devtype=MAPI_DEVICE_NAPATECH_NT;
      inst->hwinfo.devid=inst->id;
      inst->hwinfo.pkts=0;

      DEBUG_CMD(Debug_Message("Reading from trace file: %s", inst->name));

      return mapid_add_flow(&inst->mapidlib,fd,&inst->hwinfo,NULL);
    }

  i=flist_get(devlist,devid);

  i->hwinfo.offline=0;

  *devtype=MAPI_DEVICE_NAPATECH_NT;

  //Open device if it is not already open
  if (i->napatechhandle == NULL)
    {

  /* Open the correct card. */
      DEBUG_CMD(Debug_Message("mapinapatechdrv: mapidrv_create_flow; Trying to open NTCI based adapter #%d\n", 0));
  if(strstr(i->name, "xyxs") != NULL) {
    /* X card series. */
    DEBUG_CMD(Debug_Message("mapinapatechdrv: mapidrv_create_flow; Opening X card series."));
    i->napatechhandle = NTCI_OpenCard(NTCI_CARD_TYPE_ANY, 0);
  } else if(strstr(i->name, "ntx") != NULL) {
    DEBUG_CMD(Debug_Message("mapinapatechdrv: mapidrv_create_flow; Opening ntxc card series."));
    i->napatechhandle = NTCI_OpenCard(NTCI_ANY_NAPATECH_CARD_TYPE, 0);
  }
  if(i->napatechhandle==NULL) {
    DEBUG_CMD(Debug_Message("mapinapatechdrv: mapidrv_create_flow; Failed to open adapter.\n"));
    return NTCI_ERRCODE_NO_DEVICE_OPEN; // TODO
  }

  i->hwinfo.devfd = (int)i->napatechhandle;
  ((napa_nt_adapterinfo_t *)i->hwinfo.adapterinfo)->napatechhandle = i->napatechhandle;

  i->hwinfo.cap_length=0;
  /* TODO cap_length from hw */
  if (i->hwinfo.cap_length==0) {
    DEBUG_CMD(Debug_Message("WARNING: Could not get info hardware-info, using default = 1500"));
    i->hwinfo.cap_length=1500;
  }
  i->hwinfo.link_type=DLT_EN10MB; // TODO


  DEBUG_CMD(Debug_Message("mapinapatechdrv: mapidrv_create_flow; NTCI_CardIdentification() = %d", NTCI_CardIdentification(i->napatechhandle)));


  if((result = NTCI_GetCapabilities(i->napatechhandle,
                                    CAPID_HARDWARE,
                                    NOT_SUB_CAPABILITIES,
                                    STID_CARD_HARDWARE_CAPABILITIES_TYPE1,
                                    &cardCapabilities)) != NTCI_ERRCODE_SUCCESS) {

    DEBUG_CMD(Debug_Message(stderr, "Error finding adapter capabilities: %i\n", result));
  }

  channelsBitmask = cardCapabilities.totalChannelsBitmask;

  if (NTCI_CardIdentification(i->napatechhandle)==NT_CARD_TYPE) {

  /* Check if we need to use NTPL to set up feeds. */
  if((result = NTCI_GetCapabilities(i->napatechhandle,
                                    CAPID_VERSION,
                                    NOT_SUB_CAPABILITIES,
                                    STID_CARD_HARDWARE_VERSION_CAPABILITIES_TYPE3,
                                    &data3)) != NTCI_ERRCODE_SUCCESS) {
    DEBUG_CMD(Debug_Message(stderr, "Error finding HW capabilities: %i\n", result));
  }

  switch (data3.AdapterCard.dwInfoType) {
  case 1:
    if((uint16_t)((data3.AdapterCard.u.InfoType1.qwFpgaId>>8)&0xFF) == 32) {
      if(system("grep \"disableMultiFeed\" /opt/napatech/config/default.cfg > /dev/null") == 0) {
        if(system("grep \"#disableMultiFeed\" /opt/napatech/config/default.cfg > /dev/null") != 0) {
          if(system("grep disableMultiFeed /opt/napatech/config/default.cfg | grep 0 > /dev/null") == 0) {
            channelsBitmask = 0;
          }
        } else {
          channelsBitmask = 0;
        }
      } else {
        channelsBitmask = 0;
      }
    }
    break;
  case 2:
    if((uint16_t)((data3.AdapterCard.u.InfoType2.qwFpgaId>>8)&0xFF) == 32) {
      if(system("grep \"disableMultiFeed\" /opt/napatech/config/default.cfg > /dev/null") == 0) {
        if(system("grep \"#disableMultiFeed\" /opt/napatech/config/default.cfg > /dev/null") != 0) {
          if(system("grep disableMultiFeed /opt/napatech/config/default.cfg | grep 0 > /dev/null") == 0) {
            channelsBitmask = 0;
          }
        } else {
          channelsBitmask = 0;
        }
      } else {
        channelsBitmask = 0;
      }
    }
    break;
  default:
    // DEBUG_MSG(Debug_Message("Unsupported FPGA!")); // ?
    return;
  }

  // FIXME: This completely discards the previous MultiFeed check, maybe it (the check) is unnecessary?
  channelsBitmask = cardCapabilities.totalChannelsBitmask;

  } /* if (NTCI_CardIdentification(i->napatechhandle)==NT_CARD_TYPE) */

  i->hwinfo.devtype=MAPI_DEVICE_NAPATECH_NT;
  i->hwinfo.devid=i->id;
  i->hwinfo.pkts=0;
  ((napa_nt_adapterinfo_t *)i->hwinfo.adapterinfo)->channelsBitmask = channelsBitmask;


  /* Set up the packet feed engine for a single feed.
   *
   * The feedPriorities array is used to assign the
   * priorities of different feeds when creating multiple
   * simultaneous feeds; in this example it is redundant
   * as only one entry is required */

  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_create_flow; NTCI_SetupPacketFeedEngine(%d, %d, %d)", i->napatechhandle, channelsBitmask, feedPriorities[0]));

  /*  if((result = NTCI_SetupPacketFeedEngine(i->napatechhandle, 1, feedPriorities)) != NTCI_ERRCODE_SUCCESS) {
  // DEBUG_CMD(Debug_Message("Failed to initialise packet feed engine (%i)\n", result)); //stderr
    NTCI_CloseCard(i->napatechhandle);
    return -1;
    }*/


  /* Create the packet feed.
   *
   * First, initialise the feedConfig structure */
  /* provide packets in sections */
  feedConfig.bufferType = BUFFER_SECTION;

  /* hardware native timestamps */
  feedConfig.timestampType = TIMESTAMP_PCAP_NANOTIME;

  /* do not deliver corrupted packets */
  feedConfig.dropErroredPacketsFlag = 0;

  /* slicing is disabled */
  feedConfig.sliceLength = 0;

  /* large samples are used: these better handle network
   * traffic fluctuations */
  feedConfig.bufferBehaviour = SMALL_REGULAR_SAMPLES;

  /* Create the packet feed.
   *
   * PACKET_FEED_SOURCE_SAMPLED is used to specify real time
   * sampling of network traffic. */
  /*  if((result = NTCI_CreatePacketFeed(i->napatechhandle,
                                     0,
                                     channelsBitmask,
                                     PACKET_FEED_SOURCE_SAMPLED,
                                     PACKET_FEED_DESTINATION_EXTERNAL,
                                     STID_FEED_CONFIG_SAMPLED_TYPE2,
                                     &feedConfig,
                                     &i->packetfeedhandle)) != NTCI_ERRCODE_SUCCESS) {
    DEBUG_CMD(Debug_Message("Failed to create a packet feed (%i)\n", result)); //stderr
    NTCI_CloseCard(i->napatechhandle);
    return -1;
    }*/
  
  ((napa_nt_adapterinfo_t *)i->hwinfo.adapterinfo)->packetfeedhandle = i->packetfeedhandle;

  //Connnect to feed
  FeedDescriptionType2_t descr;

  if((result = NTCI_GetPacketFeedDescription(i->napatechhandle,
                                     i->name[3]-'0',
                                     STID_FEED_DESCRIPTION_TYPE2,
                                     &descr)) != NTCI_ERRCODE_SUCCESS) {
    DEBUG_CMD(Debug_Message("Failed to get packet feed (%i)\n", result)); //stderr
    NTCI_CloseCard(i->napatechhandle);
    return -1;
    }

  i->packetfeedhandle=descr.handle;
  channelsBitmask=descr.channelsBitmask;

  // i->packetfeedhandle = packetFeedHandle;

  if((result = NTCI_StartPacketFeed(i->napatechhandle, i->packetfeedhandle)) != NTCI_ERRCODE_SUCCESS) {
    DEBUG_CMD(Debug_Message("Error while starting packet feed (%i)\n", result)); // stderr
    NTCI_CloseCard(i->napatechhandle);
    return -1;
  }

  /* find the location of the feed buffer where new
   * data will be stored */
  if((result = NTCI_GetPacketFeedBuffers(i->napatechhandle,
                                         i->packetfeedhandle,
                                         STID_FEED_BUFFER_INFORMATION_TYPE1,
                                         &i->bufferInfo)) != NTCI_ERRCODE_SUCCESS) {
    DEBUG_CMD(Debug_Message("Unable to retrieve the location of the feed buffer.\n")); // stderr
    NTCI_CloseCard(i->napatechhandle);
    return -1;
  }


      //Start processing thread
      if (pthread_attr_init (&i->th_attr) != 0)
        {
          DEBUG_CMD(Debug_Message("ERROR: pthread_attr_init failed"));
          return DAGDRV_PTHR_ERR; // TODO
        }

      if (pthread_create(&i->th_proc, &i->th_attr, (void *) mapidrv_proc_loop, (void *) &(i->id)) != 0)
        {
          DEBUG_CMD(Debug_Message("ERROR: pthread_create failed"));
          return DAGDRV_PTHR_ERR; // TODO
        }
     }

  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_create_flow_; i->napatechhandle: %d; i->packetfeedhandle: %d", i->napatechhandle, i->packetfeedhandle));

  return   mapid_add_flow(&i->mapidlib,fd,&i->hwinfo,NULL);
}

int
mapidrv_connect (int devid,int fd)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_connect"));

  int ret;
  napatech_instance_t *i=flist_get(devlist,devid);
  if(i == NULL)
  	return -1;

  ret=mapid_connect(&i->mapidlib,fd);

  if(i->hwinfo.offline==4) {
    if (pthread_attr_init (&i->th_attr) != 0)
      {
		DEBUG_CMD(Debug_Message("ERROR: pthread_attr_init failed"));
		return NICDRV_PTHR_ERR;
      }
    if (pthread_create
		(&i->th_proc, &i->th_attr, (void *) mapidrv_offline_proc_loop, (void *) &(i->id)) != 0)
      {
		DEBUG_CMD(Debug_Message("ERROR: pthread_create failed"));
		return NICDRV_PTHR_ERR;
      }
  }
  return ret;
}

int
mapidrv_start_offline_device( int devid)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_start_offline_device"));

  napatech_instance_t *i = flist_get(devlist,devid);

  /* TODO */

  return 0;
}


int
mapidrv_close_flow (int devid,int fd)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_close_flow"));

  napatech_instance_t *i=flist_get(devlist,devid);
  int rc = mapid_close_flow(&i->mapidlib,fd);

  return rc;
}

int
mapidrv_load_library(MAPI_UNUSED int devid,char* lib)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_load_library"));

  return mapid_load_library(lib);
}

__attribute__ ((constructor))
     void init ()
{
  DEBUG_CMD(Debug_Message("napatechdrv: init"));

  devlist=malloc(sizeof(flist_t));
  flist_init(devlist);
  printf ("NAPATECH driver loaded [%s:%d]\n",__FILE__,__LINE__);
}

__attribute__ ((destructor))
     void fini ()
{
  DEBUG_CMD(Debug_Message("napatechdrv: fini"));
  BufferInformationSectionType1_t bufferInformation;
  
  napatech_instance_t *i;
  flist_node_t *n;

  n=flist_head(devlist);
  while(n) {
    i=flist_data(n);
    NTCI_ReleaseBuffer(i->napatechhandle,
		       i->packetfeedhandle,
		       STID_BUFFER_INFORMATION_SECTION_TYPE1,
		       &bufferInformation);
    NTCI_StopPacketFeed(i->napatechhandle,i->packetfeedhandle);
    n=flist_next(n);
  }

  free(devlist);
  printf ("NAPATECH driver unloaded [%s:%d]\n",__FILE__,__LINE__);
}

int
mapidrv_stats (int devid, char **devtype, struct mapi_stat *stats)
{
  DEBUG_CMD(Debug_Message("napatechdrv: mapidrv_stats"));

  napatech_instance_t *i=flist_get(devlist,devid);

  *devtype=MAPI_DEVICE_NAPATECH_NT;

  if (i!=NULL)
  {
	stats->ps_recv=i->hwinfo.pkts + i->hwinfo.pkt_drop;
	stats->ps_drop=i->hwinfo.pkt_drop;
	stats->ps_ifdrop=0;
	return 0;
  }

  return MAPI_STATS_ERROR;
}

