#include "time_tools.h"

// difference between 2 timevals
intmax_t usec_diff(const struct timeval* x, const struct timeval* y)
{
	return imaxabs(((intmax_t) x->tv_sec - y->tv_sec)
		* 1000000 + (x->tv_usec - y->tv_usec));
}

