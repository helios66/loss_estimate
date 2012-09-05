#ifndef TIMER_H
#define TIMER_H

#include <time.h>

struct timeval cur_time;
#define CURRENT_TIME (cur_time)

#define xtimercmp(a, b)			\
  (((a)->tv_sec == (b)->tv_sec) ?	\
   ((a)->tv_usec < (b)->tv_usec) :	\
   ((a)->tv_sec < (b)->tv_sec))

#define xtimeradd(a, b, result)				\
  do {							\
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;	\
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;	\
    if ((result)->tv_usec >= 1000000)			\
      {							\
	++(result)->tv_sec;				\
	(result)->tv_usec -= 1000000;			\
      }							\
  } while (0)

#define xtimersub(a, b, result)				\
  do {							\
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;	\
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;	\
    if ((result)->tv_usec < 0) {			\
      --(result)->tv_sec;				\
      (result)->tv_usec += 1000000;			\
    }							\
  } while (0)

#endif
