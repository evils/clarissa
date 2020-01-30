#pragma once

#define _GNU_SOURCE
#define VERSION "v0.7"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <err.h>
#include <pcap.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h> // AF_INET, AF_INET6, freebsd

#include "clarissa.h"

extern int verbosity;

void help();
void print_opts();
void handle_opts(int argc, char* argv[], struct Opts* opts);
void print_header(const struct Opts* opts);

volatile sig_atomic_t sig = 0;
void sig_handler(int signum);
