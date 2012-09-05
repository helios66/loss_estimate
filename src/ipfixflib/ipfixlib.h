#ifndef IPFIXLIB_H
#define IPFIXLIB_H

#define IFP_MAX_REC_SIZE 2000
typedef struct 
{
  unsigned long recno;
  unsigned size;
  char bytes[IFP_MAX_REC_SIZE];
} ifp_dgram_t;

#endif
