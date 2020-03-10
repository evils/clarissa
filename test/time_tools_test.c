#include <libtq/test.h>
#include "../src/time_tools.c"
#include "../src/time_tools.h"

TQ_TEST("usec_diff/same")
{
	struct timeval x = {1, 1};

	if ( !usec_diff(&x, &x) )
		return 1;

	return 0;
}

TQ_TEST("usec_diff/different")
{
	struct timeval x, y;
	x.tv_sec = 1;
	x.tv_usec = 1;
	y.tv_sec = 2;
	y.tv_usec = 2;

	if ( (usec_diff(&x, &y) == 1000001)
	  && (usec_diff(&y, &x) == 1000001) )
		return 1;

	return 0;
}

TQ_TEST("usec_diff/1us")
{
	struct timeval x, y;
	x.tv_sec = 1;
	x.tv_usec = 1;
	y.tv_sec = 1;
	y.tv_usec = 2;

	if (usec_diff(&x, &y) )
		return 1;

	return 0;
}
