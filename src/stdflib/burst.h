#ifndef __BURST_H__
#define __BURST_H__

typedef struct burst_category {
  unsigned long bytes;
  unsigned long packets;
  unsigned long bursts;
  unsigned long gap_bytes;
  unsigned long gaps;
} burst_category_t;

#endif
