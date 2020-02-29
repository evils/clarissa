#pragma once

#define _GNU_SOURCE
#define VERSION "v1.0"

// number of things in the poll
#define POLL_N 2

// more defaults at handle_opts()
// these are reused outside of that
#define DEFAULT_NAGS 4
#define DEFAULT_TIMEOUT 5000

// output path where the socket is found
#define PATH "/var/run/clar"

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

#include <sys/un.h>	// sockaddr_un
#include <fcntl.h>	// fcntl()
#include <poll.h>	// poll(), POLLIN
#include <dirent.h>	// struct dirent, opendir(), readdir()
#include <sys/stat.h>	// stat(), S_ISSOCK()

#include "clarissa.h"

extern int verbosity;

int clarissa(int argc, char* argv[]);
int clar_cat(int argc, char* argv[]);
int s_cat(char* sock, bool header);
void cat_help();

void help();
void print_opts();
void handle_opts(int argc, char* argv[], struct Opts* opts);
void print_header(const struct Opts* opts);

volatile sig_atomic_t sig = 0;
void sig_handler(int signum);

void handle_con(const int sock_d, int sock_v, struct Addrss** head);
void solve_zombies();
