#include "main.h"

int main(int argc, char* argv[])
{
	if (argc > 1 && !strncmp(argv[1], "cat", 3))
	{
		clar_cat(--argc, ++argv);
		return 0;
	}
	else return clarissa(argc, argv);
}

int clarissa(int argc, char* argv[])
{
	// options setup
	struct Opts opts;
	memset(&opts, 0, sizeof(opts));
	handle_opts(argc, argv, &opts);

	// startup header
	if (!opts.run)
	{
		if (verbosity < 2) verbosity = 2;
		print_header(&opts);
		goto end_header;
	}
	else print_header(&opts);

	// pcap setup
	// errbuff, handle and dev are in the opts struct
	struct pcap_pkthdr* header;
	const uint8_t* frame;

	// clarissa setup
	// more in the opts struct
	struct Addrss* head = NULL;
	struct Addrss addrss;
	struct timeval now, last_print, checked = {0};
	// can do at least 420 packets per second, ~100 days with 32b
	// not in opts so that only describes config state
	uint64_t count = 0;

	// socket setup
	int sock_d, sock_v, pcap_fd;
	struct sockaddr_un remote;

	// not in socket_output == true block so sock_d is initialized
	if ((sock_d = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
		err(1, "Failed to create socket");
	}

	if (opts.socket_output == true)
	{
		struct sockaddr_un local;
		// TODO move this to a separate function
		// maybe move more around here away...
		struct stat st = {0};
		if (stat(PATH, &st) == -1)
		{
			if (mkdir(PATH, 0755) == -1)
			{
				// not sure if mkdir sets errno
				err(1, "Failed to create output directory");
			}
			if (verbosity > 2)
			{
				warnx("created "PATH);
			}
		}

		int snl = snprintf(local.sun_path
				, sizeof(local.sun_path)
				, "%s", opts.socket);
		if (snl == sizeof(local.sun_path))
		{
			errx(1, "socket path is too long");
		}

		int flags = fcntl(sock_d, F_GETFL, 0);
		if (flags == -1)
		{
			err(1, "Failed to get socket flags");
		}
		if (fcntl(sock_d, F_SETFL, flags | O_NONBLOCK) == -1)
		{
			err(1, "Failed to set O_NONBLOCK on socket");
		}

		// check if local.sun_path is already in use
		int s;
		struct sockaddr_un check;
		if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		{
			err(1, "Failed to create socket (check)");
		}
		check.sun_family = AF_UNIX;
		strcpy(check.sun_path, local.sun_path);
		if (connect(s, (struct sockaddr*)&check, sizeof(check)) == -1)
		{
			if (verbosity > 3)
			{
				warnx("socket does not exist yet, creating %s"
				, check.sun_path);
			}
		}
		else
		{
			errx(1, "socket already in use: %s\n"
			"change socket name with --socket, or disable socket output with -S", check.sun_path);
		}

		unlink(local.sun_path);
		local.sun_family = AF_UNIX;
		if (bind(sock_d, (struct sockaddr*)&local, sizeof(local)) == -1)
		{
			err(1, "Failed to bind socket");
		}

		if (chmod(opts.socket, 0666) != 0)
		{
			err(1, "Failed to set socket permissions");
		}

		if (listen(sock_d, 5) == -1) // "5 is way more than enough"
		{
			err(1, "Failed to set socket to listening mode");
		}
	}

	// set up poll() (not select())
	pcap_fd = pcap_get_selectable_fd(opts.l_handle);
	if (pcap_fd == PCAP_ERROR)
	{
		pcap_perror(opts.l_handle, "pcap_fd setup: ");
		exit(1);
	}

	struct pollfd fds[POLL_N];
	memset(fds, 0, sizeof(fds));
	fds[0].fd = pcap_fd;
	fds[0].events = POLLIN;
	if (opts.socket_output == true)
	{
		fds[1].fd = sock_d;
		fds[1].events = POLLIN;
	}

	solve_zombies();

	signal(SIGINT, &sig_handler);
	signal(SIGTERM, &sig_handler);

	int child = -1;

	// capture, extract and update list of addresses
	for (;!sig;)
	{
		// POLL_* #defined in main.h
		if (poll(fds, POLL_N, opts.interval / 2000) < 1)
		{
			if (verbosity > 4)
				warnx("poll() timed out or failed, retrying");
			continue;
		}

		// pcap_fd
		if (fds[0].revents & POLLIN)
		{

			int result = pcap_next_ex(opts.l_handle,
					&header, &frame);
			switch (result)
			{
				case -2:
					printf("End of savefile reached.\n");
					goto end;
				case -1:
					pcap_perror(opts.l_handle,
						"Reading packet: ");
					continue;
				case 0:
					warnx
					("Packet buffer timeout expired.");
					gettimeofday(&now, NULL);
					break;
				case 1:
				{
					addrss = get_addrss(opts.l_handle,
							frame, header);

					// zero IP if not in the set subnet
					// or use the host's subnet
					if (addrss.ip)
					subnet_filter   ( addrss.v6
							? addrss.ipv6
							: addrss.ipv4
					, opts.cidr	? &opts.subnet
							: &opts.host.subnet
					, addrss.v6);

					// go again if extraction failed
					// a non-zero MAC address is required
					if (!addrss_valid(&addrss)) continue;

					if (verbosity > 4)
					{
						print_mac(addrss.mac);

						if (addrss.ip)
						print_ip( addrss.v6
							? addrss.ipv6
							: addrss.ipv4
							, addrss.v6);
					}

					addrss_list_add(&head, &addrss);

					// use arrival time to be consistent
					// regardless of pcap to_ms
					now = addrss.ts;
					break;
				}
				default:
					warnx("Unexpected return value "
						"from pcap_next_ex: %d",
						result);
					continue;
			}
		}

		// socket
		if (fds[1].revents & POLLIN)
		{
			socklen_t size = sizeof(remote);
			sock_v = accept(sock_d
					, (struct sockaddr*)&remote
					, &size);

			if (sock_v == -1)
			{
				warnx("Parent's accept() failed, retrying");
				continue;
			}

			child = fork();
			if (child < 0)
			{
				warnx("Failed to fork(), retrying");
				continue;
			}
			else if (child == 0)
			{
				handle_con(sock_d, sock_v, &head);
				goto end;
			}

			close(sock_v);
		}

		if (usec_diff(&now, &checked) > opts.interval)
		{
			checked = now;

			// cull those that have been nagged enough
			addrss_list_cull
				(&head, &now, opts.timeout,
					opts.nags);

			// and nag the survivors
			addrss_list_nag
				(&head, &now, opts.timeout,
					&opts, &count);
		}

		// output the list to a file
		if (opts.print_interval
				&& (opts.print_interval
					< usec_diff(&now, &last_print
						)))
		{
			last_print = now;
			dump_state(opts.print_filename, head);
		}
	}

	// stats footer
	// TODO, figure out if i always want this
	// shows up in systemctl status if stopped
	if (true)
	{
		struct pcap_stat ps = {0};
		if (!pcap_stats(opts.l_handle, &ps))
		{
			printf
			("\nclarissa sent\t\t%lu\n", count);
			printf
			("clarissa received\t%i\n", ps.ps_recv);
			printf
			("buffer dropped\t\t%i\n", ps.ps_drop);
			printf
			("interface dropped\t%i\n", ps.ps_ifdrop);
		}
	}

// cleanup
end:
	if (child != 0)
	{
		close(sock_d);
		remove(opts.socket);

		// leave will if this was requested
		// , if the input is a file
		// or file output (interval) was set
		if (opts.will || opts.from_file
			|| opts.print_interval)
		{
			dump_state(opts.print_filename, head);
			printf("Left list in will file: %s\n"
					, opts.print_filename);
		}

		fprintf(stderr, "\nStopped by:\t\t");
		switch (sig)
		{
			case SIGINT:
				fprintf(stderr, "SIGINT");
				break;
			case SIGTERM:
				fprintf(stderr, "SIGTERM");
				break;
		}
		printf("\n");
	}

	for (struct Addrss* tmp; head != NULL;)
	{
		tmp = head;
		head = head->next;
		free(tmp);
	}

// and the stuff that's used by the header
end_header:

	if (opts.l_handle) pcap_close(opts.l_handle);
	if (opts.s_handle) pcap_close(opts.s_handle);

	// these should all get asprintf'd
	// can't copy optarg pointer because that can't be freed
	free(opts.print_filename);
	free(opts.socket);
	free(opts.l_dev);
	free(opts.s_dev);
	return 0;
}

void clar_cat(int argc, char* argv[])
{
	// handle options and arguments
	// if no arguments were given,
	// default to the first item in PATH
	int opt;

	bool socket 	= true;
	bool file 	= false;
	bool header	= true;
	int args	= 0;

	static struct option long_options[] =
	{
		{"file",	no_argument,	0,	'f'},
		{"file_off",	no_argument,	0,	'F'},
		{"socket",	no_argument,	0,	's'},
		{"socket_off",	no_argument,	0,	'S'},
		{"all_off",	no_argument,	0,	'A'},
		{"raw",		no_argument,	0,	'r'},
		{"all",		no_argument,	0,	'a'},
		{"help",	no_argument,	0,	'h'},
		{"version",	no_argument,	0,	'v'}
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
		for (struct dirent* dir_e = readdir(dir_p)
			; dir_e != NULL; dir_e = readdir(dir_p))
		{
			if ((dir_e->d_type != DT_SOCK)
			&& (dir_e->d_type != DT_REG))
				continue;

			char* full_path;
			if (asprintf(&full_path, "%s/%s"
				, PATH, dir_e->d_name) == -1)
			{
				errx(1, "Failed to save full path");
			}

			cat_cat(full_path, socket, file, header);
			exit(0);
		}

		errx(1, "No socket found in "PATH);
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

	char c;
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

// non blocking alternative to wait()
void solve_zombies()
{
	struct sigaction action = { .sa_handler = SIG_IGN };
	sigaction(SIGCHLD, &action, NULL);
}

void handle_con(const int sock_d, int sock_v, struct Addrss** head)
{
	struct sockaddr_un remote;
	socklen_t size = sizeof(remote);
	do
	{
		// send the header
		char* string;
		if (asprint_clar_header(&string) == -1)
		{
			warnx("Dropping socket connection");
			close(sock_v);
			free(string);
			return;
		}
		send(sock_v, string, strlen(string), 0);
		free(string);

		// send out the list
		for (struct Addrss** current = head;
				*current != NULL;
				current = &((*current)->next))
		{
			if (asprint_clar(&string, *current) != 0)
			{
				warnx("Dropping socket connection");
				close(sock_v);
				free(string);
				break;
			}
			send(sock_v, string, strlen(string), 0);

			free(string);
		}
		close(sock_v);
		sock_v = accept(sock_d, (struct sockaddr*)&remote, &size);
	}
	while (sock_v > 0);
}

void sig_handler(int signum)
{
	sig = signum;
}

// print help header and options
void help()
{
	printf(
		"Usage:\n"
		"       clarissa [-hHvVqauw] [--interface I] [--listen l]\n"
		"                [--interval i] [--nags n] [--timeout t] [--cidr c]\n"
		"                [--output_file o] [--output_interval O]\n"
		"                [--file f] [--socket s]\n"
		"       clarissa cat [-fFsSArahv] [file... socket...]\n\n"
		"Clarissa keeps a list of all connected devices on a network.\n"
		"It attempts to keep it as complete and up to date as possible.\n"
	      );

	print_opts();
}

void print_opts()
{
	printf(
		"\n"VERSION"\n\n"
		"Options:\n"
		"   Long            Short\n"
		"--help              -h\n"
		"   show the help message and exit\n"
		"--header            -H\n"
		"   show the Header and exit\n"
		"--verbose           -v\n"
		"   increase verbosity\n"
		"   shows: err & warn < MAC < IP < chatty < debug < vomit\n"
		"--version           -V\n"
		"   show the Version\n"
		"--quiet             -q\n"
		"   don't send out packets (equivalent to -n 0)\n"
		"--abstemious        -a\n"
		"   don't set the interface to promiscuous mode\n"
		"--unbuffered        -u\n"
		"   don't buffer packets (use immediate mode)\n"
		"--stop_socket       -S\n"
		"   don't output use a Socket for output\n"
		"--will              -w\n"
		"   leave a Will file containing the list at exit\n"
		"\nRequiring an argument:\n\n"
		"   Long            Short       Default\n"
		"--interface         -I   pcap auto select\n"
		"   set the primary Interface\n"
		"--listen            -l   Interface\n"
		"   set the Listening interface\n"
		"--interval          -i   Timeout / Nags\n"
		"   set the interval (in milliseconds)\n"
		"--nags              -n   %i\n"
		"   set how many times an entry can time out\n"
		"   before being removed from the list (sends a frame on time out)\n"
		//"--nags              -n   %i\n"
		//"   set how many times to attempt to contact an entry before removing it from the list\n"
		//"--nags              -n   %i\n"
		//"   set the amount of frames to send to a timed out / unresponsive entry before removing it from the list\n"
		//"--nags              -n   %i\n"
		//"   set how many times a timed out entry gets send a frame before being removed from the list\n"
		"--timeout           -t   %i\n"
		"   set the Timeout for an entry (wait time for nags in ms)\n"
		"--cidr              -c   Interface's IPv4 subnet\n"
		"   set a CIDR subnet to which IPv4 activity is limited\n"
		"--file              -f   none\n"
		"   set an input File (pcap file, works with - (stdin))\n"
		"--socket            -s   "PATH"/[Interface]_[subnet]-[mask]\n"
		"   set the output socket name (incl. path)\n"
		"--output_file       -o   [socket].clar\n"
		"   set the output filename\n"
		"--output_interval   -O   0\n"
		"   set the Output interval (in ms), 0 = no periodic output\n"
		, DEFAULT_NAGS, DEFAULT_TIMEOUT
	      );
}

void handle_opts(int argc, char* argv[], struct Opts* opts)
{
	// defaults
	opts->nags 		= DEFAULT_NAGS;
	opts->timeout 		= DEFAULT_TIMEOUT * 1000; // (ms to µs)
	opts->run		= true;
	opts->immediate		= false;
	opts->promiscuous 	= true;
	opts->socket_output	= true;
	verbosity 		= 0;

	// local helpers
	bool version	= false;
	bool nags_set 	= false;
	char* auto_dev	= NULL;
	char* auto_name	= NULL;
	char* filename	= NULL;

	int opt;

	static struct option long_options[] =
	{
		{"version",		no_argument, 0,		'V'},
		{"verbose",		no_argument, 0, 	'v'},
		{"help",		no_argument, 0,		'h'},
		{"header",		no_argument, 0,		'H'},
		{"abstemious",		no_argument, 0,		'a'},
		{"quiet",		no_argument, 0,		'q'},
		{"unbuffered",		no_argument, 0,		'u'},
		{"will",		no_argument, 0,		'w'},
		{"stop_socket",		no_argument, 0,		'S'},
		{"listen",		required_argument, 0,	'l'},
		{"interface",		required_argument, 0,	'I'},
		{"interval",		required_argument, 0,	'i'},
		{"nags", 		required_argument, 0,	'n'},
		{"timeout", 		required_argument, 0,	't'},
		{"cidr",		required_argument, 0,	'c'},
		{"file", 		required_argument, 0,	'f'},
		{"output_file", 	required_argument, 0,	'o'},
		{"output_interval",	required_argument, 0,	'O'},
		{"socket",		required_argument, 0,	's'}
	};
	int option_index = 0;
	while ((opt = getopt_long(argc, argv, ":wc:SuHVvi:an:l:t:qf:I:s:ho:O:",
				long_options, &option_index)) != -1)
	{
		switch (opt)
		{
			case 'w':
				opts->will = true;
				break;
			case 's':
				// save socket path name
				if (asprintf(&opts->socket, "%s", optarg) == -1)
				{
					errx(1, "Failed to save given socket path name");
				}
				break;
			case 'S':
				opts->socket_output = false;
				break;
			case 'u':
				opts->immediate = true;
				break;
			case 'H':
				opts->run = false;
				break;
			case 'V':
				version = true;
				break;
			case 'v':
				verbosity++;
				break;
			case 'i':
				// get interval in ms
				opts->interval = (atoi(optarg) * 1000);
				break;
			case 'a':
				opts->promiscuous = false;
				break;
			case 'n':
				// get number times to nag an entry
				if (nags_set == false)
				{
					opts->nags = atoi(optarg);
					nags_set = true;
				}
				break;
			case 'l':
				// get the listen interface
				if (asprintf(&opts->l_dev, "%s", optarg) == -1)
				{
					errx(1, "Failed to save given listening interface name");
				}
				break;
			case 't':
				// get timeout in ms
				opts->timeout = (atoi(optarg) * 1000);
				break;
			case 'q':
				// quiet, may be redundant
				opts->nags = 0;
				nags_set = true;
				break;
			case 'f':
				// save filename
				if (asprintf(&filename, "%s", optarg) == -1)
				{
					errx(1, "Failed to save given file name");
				}
				opts->from_file = true;
				break;
			case 'I':
				// get the sending interface
				if (asprintf(&opts->s_dev, "%s", optarg) == -1)
				{
					errx(1, "Failed to save given sending interface name");
				}
				break;
			case 'c':
				if (opts->cidr)
				{
					errx(1,
				"Multiple CIDR subnets currently not supported");
				}
				// parse provided CIDR notation
				if (!get_cidr(&opts->subnet, optarg))
				{
					// get_cidr uses inet_pton, which may set errno
					err(1, "Failed to parse CIDR");
				}
				else opts->cidr += 1;
				break;
			case 'h':
				help();
				exit(0);
			case 'o':
				if (asprintf(&opts->print_filename, "%s", optarg) == -1)
				{
					errx(1, "Failed to save given output filename");
				}
				break;
			case 'O':
				opts->print_interval = atoi(optarg) * 1000;
				if (opts->print_interval < 0) {
					warnx("Failed to parse print interval");
				}
				break;
			case ':':
				errx(1, "%c\trequires an argument!", optopt);
			default:
				// usage
				print_opts();
				exit(1);
		}
	}

	if (version == true)
	{
		printf("Version:\t");
		if (verbosity || opts->run == false) printf("\t");
		printf("%s\n", VERSION);
	}

	if (!opts->interval)
	{
		opts->interval =
			opts->timeout / (opts->nags ? opts->nags : 1);
	}

	// can't listen on loopback
	// set to NULL to allow fallback to s_dev or auto_dev
	if (opts->l_dev && !strncmp(opts->l_dev, "lo", 2))
	{
		warnx("Listening on loopback currently not supported"
		", falling back on something else.");
		free(opts->l_dev);
		opts->l_dev = NULL;
	}

	// can't send to the "any" interface
	// set to null to allow fallback to auto_dev
	if (opts->s_dev && !strncmp(opts->s_dev, "any", 3))
	{
		warnx("Sending to \"any\" currently not supported"
		", falling back on the first available interface.");
		free(opts->s_dev);
		opts->s_dev = NULL;
	}

	// auto select dev if needed
	if (!opts->l_dev || !opts->s_dev
		|| (opts->s_dev && !strncmp(opts->s_dev, "lo", 2)))
	{
		pcap_if_t* devs;
		if (pcap_findalldevs(&devs, opts->errbuf)
			|| devs == NULL)
		{
			errx(1, "Failed to find an interface\n");
		}

		if (devs->description != NULL && verbosity > 2)
		{
			printf("%s\n", devs->description);
		}

		if (asprintf(&auto_dev, "%s", devs->name) == -1)
		{
			errx(1, "Failed to save found listen interface name");
		}

		pcap_freealldevs(devs);
	}

	// fall back on s_dev or auto_dev
	if (!opts->l_dev)
	{
		if (opts->s_dev && strncmp(opts->s_dev, "lo", 2))
		{
			if (asprintf(&opts->l_dev, "%s", opts->s_dev)
				== -1)
			{
				errx(1, "Failed to write s_dev to l_dev");
			}
		}
		else
		{
			if (asprintf(&opts->l_dev, "%s", auto_dev)
				== -1)
			{
				errx(1, "Failed to write auto_dev to l_dev");
			}
		}
	}

	// fall back on auto_dev
	if (!opts->s_dev)
	{
		if (asprintf(&opts->s_dev, "%s", auto_dev) == -1)
		{
			errx(1, "Failed to save auto_dev to s_dev");
		}
	}

	// assert everything's set up
	// TODO, support listening from file and sending to stdout or file
	// this would involve no devices...
	if (!(opts->l_dev && opts->s_dev))
	{
		errx(1, "Failed to set up device(s)");
	}

	// make l_handle
	if (!filename)
	{
		opts->l_handle = pcap_create(opts->l_dev,
			opts->errbuf);
		if (opts->l_handle == NULL)
		{
			errx(1, "pcap failed to create l_handle: %s",
				opts->errbuf);
		}

		// CAPLEN is probably 74
		if (pcap_set_snaplen(opts->l_handle, CAPLEN))
		{
			warnx("Failed to set snapshot length");
		}

		if (pcap_set_promisc(opts->l_handle,
			opts->promiscuous))
		{
			warnx("Failed to set promiscuous mode");
		}

		// timeout shouldn't have an effect if immediate
		// pcap timeout = half the interval (in milliseconds)
		if (pcap_set_timeout(opts->l_handle,
			opts->interval / 2000))
		{
			warnx("Failed to set packet buffer timeout");
		}

		if (pcap_set_immediate_mode
			(opts->l_handle, opts->immediate))
		{
			warnx("Failed to set immediate mode");
		}

		int result = pcap_activate(opts->l_handle);
		switch (result)
		{
			// warnings
			case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
				warnx("set timestamp not supported");
				break;
			// warnings supported by pcap_perror()
			case PCAP_WARNING_PROMISC_NOTSUP:
				pcap_perror
				(opts->l_handle, "Activation: ");
				warnx
				("promiscuous mode not supported");
				break;
			case PCAP_WARNING:
				pcap_perror
				(opts->l_handle, "Activation: ");
				break;
			// errors
			case PCAP_ERROR_ACTIVATED:
				errx(1, "l_handle already active");
			case PCAP_ERROR_PROMISC_PERM_DENIED:
				errx
				(1, "no permission for promiscuous");
			case PCAP_ERROR_RFMON_NOTSUP:
				errx(1, "can't use monitor mode");
			case PCAP_ERROR_IFACE_NOT_UP:
				errx(1, "capture source is not up");
			// errors supported by pcap_perror()
			case PCAP_ERROR_NO_SUCH_DEVICE:
				pcap_perror
				(opts->l_handle, "Activation: ");
				errx(1, "no such capture source");
			case PCAP_ERROR_PERM_DENIED:
				pcap_perror
				(opts->l_handle, "Activation: ");
				errx
				(1, "no permission to open source");
			case PCAP_ERROR:
				pcap_perror
				(opts->l_handle, "Activation: ");
				exit(1);
		}
	}

	// separate sending interface
	if (opts->nags)
	{
		opts->s_handle = pcap_open_live(opts->s_dev, 0, 0, 0,
			opts->errbuf);
		if (opts->s_handle == NULL)
		{
			errx(1, "pcap failed to create s_handle: %s",
				opts->errbuf);
		}
	};

	// one interface
	if (!opts->s_handle && opts->l_handle)
	{
		opts->s_handle = opts->l_handle;
	};

	// overwrite l_handle if a file input is being used
	if (filename)
	{
		opts->l_handle = pcap_open_offline(filename, opts->errbuf);
	}

	// fill in the host ID
	get_if_mac(opts->host.mac, opts->s_dev);
	get_if_ipv4_subnet(&opts->host.subnet, opts);
	get_if_ip(opts->host.ipv4, opts->s_dev, AF_INET, opts->errbuf);
	get_if_ip(opts->host.ipv6, opts->s_dev, AF_INET6,opts->errbuf);

	// if auto_name is required
	if (!opts->socket || opts->print_filename)
	{
		char* ip;
		// subnet.ip is IPv6 or mapped v4
		// but asprint_ip correctly does mapped handling
		// i want just the dotted quad
		asprint_ip(&ip, opts->cidr ? opts->subnet.ip + 12
				: opts->host.subnet.ip + 12, false);
		if (asprintf(&auto_name
			// if reading from file
			// output to current directory
			, filename ? "clar_parsed-%s"
			: PATH"/%s_%s-%i"
			, filename ? filename : opts->l_dev
			, ip
			, (opts->cidr
				? opts->subnet.mask
				: opts->host.subnet.mask) - 96)
			== -1)
		{
			errx(1, "Failed to set the auto_name");
		}
		free(ip);
	}

	if (!opts->print_filename)
	{
		if (asprintf(&opts->print_filename, "%s.clar", auto_name)
			== -1)
		{
			errx(1, "Failed to set the output filename");
		}
	}

	if (!opts->socket)
	{
		if (asprintf(&opts->socket, "%s", auto_name) == -1)
		{
			errx(1, "Failed to set the output socket path name");
		}
	}

	if (auto_dev)	free(auto_dev);
	if (auto_name)	free(auto_name);
}

void print_header(const struct Opts* opts)
{
	if (!verbosity)
		fprintf(stderr, "Verbosity:\t%d\n\n", verbosity);

// input block
	if (!opts->l_dev) printf("Using file input\n\n");
	if (verbosity && opts->s_dev)
	{
		if (strcmp(opts->l_dev, opts->s_dev))
		{
			printf("Listen interface:\t%s\n", opts->l_dev);
		}
		printf("Host interface:\t\t%s\n", opts->s_dev);
		printf("Host MAC address:\t");
		print_mac(opts->host.mac);
		if (verbosity > 1)
		{
			printf("Host IPv4 address:\t");
			print_ip(opts->host.ipv4, false);
			printf("Host IPv6 address:\t");
			print_ip(opts->host.ipv6, true);
		}
		printf("\n");

// mode block
		if (!opts->promiscuous) printf("Interface not in promiscuous mode (abstemious)\n");
		if (opts->immediate) printf("Capturing with immediate mode (unbuffered)\n");
		if (!opts->nags) printf("Quiet (no frames will be sent)\n");
		if (!opts->promiscuous || opts->immediate
			|| !opts->nags)
		{
			printf("\n");
		}

		if (verbosity > 1)
		{
			char* ip;
			if (is_zeros(opts->subnet.ip, sizeof(opts->subnet.ip)))
			{
				// subnet block,
				// subnet.ip is IPv6 or mapped v4
				// if mapped, print it as IPv4
				bool m = is_mapped(opts->host.subnet.ip);
				asprint_ip(&ip, opts->host.subnet.ip + (m ? 12 : 0), !m);
				printf("Host IPv%d subnet:\t%s/%d\n", m ? 4 : 6,
					ip, opts->host.subnet.mask - (m ? 96 : 0));
			}
			else
			{
				bool m = is_mapped(opts->subnet.ip);
				asprint_ip(&ip, opts->subnet.ip + (m ? 12 : 0), !m);
				printf("Subnet filter:\t\t%s/%d\n",
					ip, opts->subnet.mask - (m ? 96 : 0));
			}
			free(ip);
			printf("\n");

			if (verbosity > 2)
			{
				// options block
				if (opts->nags)
				{
					printf("Nags:\t\t\t%d\n",
						opts->nags);
				}
				printf("Timeout:\t\t%dms\n",
					opts->timeout / 1000);
				printf("Interval:\t\t%dms\n",
					opts->interval / 1000);
				printf("\n");
			}
		}

// output block
		if (verbosity)
		{
			printf("Output socket");
			if (opts->socket_output == true)
			{
				printf(":\t\t%s",opts->socket);
			}
			else
			{
				printf(" disabled");
			}
			printf("\n");

			if (opts->will || opts->from_file || opts->print_interval)
			{
				printf("Output filename:\t%s\n", opts->print_filename);
			}
			if (opts->print_interval)
			{
				printf("Output interval:\t%dms\n",opts->print_interval / 1000);
			}
			printf("\n");
		}
	}
}
