#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <err.h>
#include <pcap.h>
#include <unistd.h>

#include "clarissa.h"

extern int verbosity;

int help();
int print_opts();
int handle_opts(int argc, char* argv[], struct Opts* opts);
