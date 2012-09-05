#ifndef _STATS_H
#define _STATS_H 1

typedef struct stats {
  unsigned long long count; //Number of elements
  long double sum; //Sum
  long double sum2; //Sum of square
  double max; //Maximum value
  double min; //Minimum value
} stats_t;


#endif
