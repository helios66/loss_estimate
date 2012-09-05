#ifndef _DIST_H
#define _DIST_H 1

typedef struct dist {
  unsigned long long min; //Minimum value that can be stored
  unsigned long long max; //Maximum value that can be stored
  unsigned long long intervals; //Number of intervals
  unsigned long long data[1]; //Location of the first interval
} dist_t;

#endif
