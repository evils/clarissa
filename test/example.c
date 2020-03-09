#include <libtq/test.h>

#include <err.h>

TQ_TEST("is this thing on?")
{
	// a test should return 1 on success (0 for failure)
	// and nothing to stdout
	warnx("Example returned 1 for 'success'");
	return 1;
}

