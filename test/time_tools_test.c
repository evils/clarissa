#include <libtq/test.h>
#include "../time_tools.h"

TQ_TEST("usec_diff")
{
	struct timeval x, y;
	x.tv_sec = 1;
	x.tv_usec = 1;
	y.tv_sec = 2;
	y.tv_usec = 2;

	if ( (usec_diff(&x, &x)) )
		return 0;

	if ( (usec_diff(&x, &y) == 1000001)
	  && (usec_diff(&y, &x) == 1000001) )
		return 1;

	return 0;
}
