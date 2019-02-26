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

struct Opts
{
	//pcap stuff
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	char* dev;

	// clarissa stuff
	struct Subnet subnet;
	int timeout;
	int interval;
	int nags;
	int promiscuous;
	int parsed;
};

int help();
int print_opts();
int handle_opts(int argc, char* argv[], struct Opts* opts);
