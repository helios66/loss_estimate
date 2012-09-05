#ifndef MAPINAPATECHDRV_H
#define MAPINAPATECHDRV_H

#include "NTCommonInterface.h"

typedef struct napa_nt_adapterinfo
{
  handle_t napatechhandle;
  uint32_t packetfeedhandle;
  uint32_t channelsBitmask;
} napa_nt_adapterinfo_t;

#endif
