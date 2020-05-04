#include "clarissa_cat.h"
#include "clarissa_defines.h"

#include <stdio.h>      // asprintf()
#include <stdlib.h>     // exit()
#include <unistd.h>     // close()
#include <err.h>        // err(), warnx()
#include <stdbool.h>    // type bool
#include <getopt.h>     // getopt_long()
#include <dirent.h>     // struct dirent, opendir(), readdir()
#include <sys/un.h>     // sockaddr_un
#include <sys/stat.h>   // stat(), S_ISSOCK(), S_ISREG()
#include <sys/socket.h> // socket(), connect()
#include <string.h>	// strcpy() on omnios

void cat_cat(char* path, bool sock, bool file, bool header);
void s_cat(char* path, bool header);
void f_cat(char* path, bool header);
void cat_header(char* path, bool sock, bool header);
int asprint_cat_header(char** dest);
void cat_help();

void clar_cat(int argc, char* argv[])
{
	// handle options and arguments
	// if no arguments were given,
	// default to the first item in PATH
	int opt;

	bool socket     = true;
	bool file       = false;
	bool header     = true;
	int args        = 0;

	static struct option long_options[] =
	{
		{"file",        no_argument,    0,      'f'},
		{"file_off",    no_argument,    0,      'F'},
		{"socket",      no_argument,    0,      's'},
		{"socket_off",  no_argument,    0,      'S'},
		{"all_off",     no_argument,    0,      'A'},
		{"raw",         no_argument,    0,      'r'},
		{"all",         no_argument,    0,      'a'},
		{"help",        no_argument,    0,      'h'},
		{"version",     no_argument,    0,      'v'}
	};
	int option_index = 0;
	while ((opt = getopt_long(argc, argv, "-fFsSArahv",
				long_options, &option_index)) != -1)
	{
		switch (opt)
		{
			case 'f': file = true; break;
			case 'F': file = false; break;
			case 's': socket = true; break;
			case 'S': socket = false; break;
			case 'a': file = true; socket = true; break;
			case 'A': file = false; socket = false; break;
			case 'v':
				fprintf(stderr, "Version:\t%s\n", VERSION);
				break;
			case 'h':
				cat_help();
				exit(0);
			case 'r':
				header = false;
				break;
			case 1:
				args++;
				cat_cat(optarg, socket, file, header);
				break;
			case ':':
				warnx("That option requires an argument.");
				cat_help();
				exit(1);
			case '?':
				warnx("Unknown option");
				cat_help();
				exit(1);
			default:
				cat_help();
				exit(1);
		}
	}

	// no argument, attempt to find something in PATH
	if (args <= 0)
	{
		DIR* dir_p = opendir(PATH);
		if (dir_p == NULL)
		{
			err(1, "Failed to open "PATH", does it exist?");
		}

		struct stat st;
		char* full_path;
		for (struct dirent* dir_e = readdir(dir_p)
			; dir_e != NULL; dir_e = readdir(dir_p))
		{
			if (asprintf(&full_path, "%s/%s"
				, PATH, dir_e->d_name) == -1)
			{
				errx(1, "Failed to save full path");
			}

			stat(full_path, &st);
			// check if this is a socket or regular file
			// only when we are looking for one of those
			// cannot use d_type for sake of portability
			if (	!((socket && S_ISSOCK(st.st_mode))
				|| (file && S_ISREG(st.st_mode))))
			{
				free(full_path);
				continue;
			};

			cat_cat(full_path, socket, file, header);
			free(full_path);
			free(dir_p);
			exit(0);
		}

		free(dir_p);
		errx(1, "No source found in "PATH);
	}
}

void cat_cat(char* path, bool sock, bool file, bool header)
{
	struct stat st;

	if (sock == true)
	{
		stat(path, &st);
		if (S_ISSOCK(st.st_mode))
		{
			s_cat(path, header);
		}
	}

	if (file == true)
	{
		stat(path, &st);
		if (S_ISREG(st.st_mode))
		{
			f_cat(path, header);
		}
	}
}

void s_cat(char* path, bool header)
{
	int s, t;
	struct sockaddr_un remote;
	char str[137];

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
		err(1, "Failed to create socket");
	}

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, path);
	if (connect(s, (struct sockaddr*)&remote, sizeof(remote)) == -1)
	{
		err(1, "Failed to connect to socket");
	}

	cat_header(path, true, header);

	while ((t=recv(s, str, sizeof(str), 0)) > 0)
	{
		if (fwrite(str, 1, t, stdout) != (size_t)t)
		{
			errx(1, "Failed to write line to STDOUT");
		}
	}

	close(s);
}

void f_cat(char* path, bool header)
{
	FILE* fd = fopen(path, "r");
	if (fd == NULL)
	{
		err(1, "Failed to open %s", path);
	}

	cat_header(path, false, header);

	int c;
	while ((c = fgetc(fd)) != EOF)
	{
		putchar(c);
	}

	fclose(fd);
}

void cat_header(char* path, bool sock, bool header)
{
	if (header == true)
	{
		printf("#   from   %s   %s\n"
			, sock ? "socket" : "file"
			, path);
		char* header;
		if (asprint_cat_header(&header) == -1)
		{
			errx(1, "Giving up...");
		}
		printf("%s", header);
		free(header);
	}
}

int asprint_cat_header(char** dest)
{
	if (asprintf(dest,
"#   MAC_address       MAC_time     IPv4_address     IPv4_time                 IPv6_address                 IPv6_time\n")
		== -1)
	{
		warnx("Failed to asprint cat header");
		return -1;
	}
	return 0;
}

void cat_help()
{
	printf(
		"    Long      Short   Note\n"
		"--file         -f\n"
		"   also print from regular files\n"
		"--file_off     -F    default\n"
		"   explicitly don't print from Files\n"
		"--socket       -s    default\n"
		"   explicitly print from sockets\n"
		"--socket_off   -S\n"
		"   don't print from Sockets\n"
		"--all          -a\n"
		"   print from all supported formats\n"
		"--all_off      -A   for completeness\n"
		"   print nothing\n"
		"--raw          -r\n"
		"   exclude the source and column name headers\n"
		"--version      -v\n"
		"   show the Version of this tool and exit\n"
		"--help         -h\n"
		"   show this Help message and exit\n"
	      );
}
