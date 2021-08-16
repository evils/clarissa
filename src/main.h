#pragma once

#include "clarissa.h"
#include "clarissa_cat.h"
#include "clarissa_defines.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <err.h>
#include <pcap.h>
#include <unistd.h>
#include <getopt.h>	// getopt_long()
#include <signal.h>
#include <string.h>
#include <sys/socket.h> // AF_INET, AF_INET6, freebsd
#include <poll.h>	// poll(), POLLIN

extern int verbosity;

int clarissa(int argc, char* argv[]);

void help();
void print_opts();
void handle_opts(int argc, char* argv[], struct Opts* opts);
void print_header(const struct Opts* opts);

volatile sig_atomic_t sig = 0;
void sig_handler(int signum);

void handle_con(const int sock_d, int sock_v, struct Addrss** head);
void solve_zombies();
