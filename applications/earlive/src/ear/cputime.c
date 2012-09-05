#include "cputime.h"

#include <sys/time.h>
#include <sys/resource.h>


double get_cputime(void)
{
	struct rusage ruse;
	getrusage(RUSAGE_SELF,&ruse);
	return ruse.ru_utime.tv_sec + ruse.ru_stime.tv_sec
		+ 1e-6 * (ruse.ru_utime.tv_usec + ruse.ru_stime.tv_usec);
}
