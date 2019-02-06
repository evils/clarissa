#pragma once

#include <sys/time.h>
#include <inttypes.h>

intmax_t usec_diff(struct timeval* x, struct timeval* y);
