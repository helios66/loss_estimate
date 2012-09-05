#ifndef MAPIDAGDRV_H_
#define MAPIDAGDRV_H_

typedef unsigned long long dag_counter_t;	/* Main data type for counters. */


typedef struct dag_adapterinfo {
  char *name;		/* /dev/dag0 */
  int dagfd;
  dag_card_ref_t card;
  int portcnt;		/* number of ports on the card */
} dag_adapterinfo_t;

#endif /*MAPIDAGDRV_H_*/
