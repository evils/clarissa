#pragma once

#include <sys/time.h>
#include <inttypes.h>

intmax_t usec_diff(const struct timeval* x, const struct timeval* y);
