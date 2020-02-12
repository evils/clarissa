#include "main.h"

int main(int argc, char* argv[])
{
	if (argc > 1 && !strncmp(argv[1], "cat", 3))
	{
		return clar_cat(--argc, ++argv);
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
	struct sockaddr_un local, remote;
	if ((sock_d = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
		err(1, "Failed to create socket");
	}

	int snl = snprintf(local.sun_path
			, sizeof(local.sun_path)
			, "%s", opts.socket);
	if (snl == sizeof(local.sun_path))
	{
		err(1, "Socket path is too long");
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

	unlink(local.sun_path);
	local.sun_family = AF_UNIX;
	if (bind(sock_d, (struct sockaddr*)&local,
				strlen(local.sun_path)
				+ sizeof(local.sun_family))
			== -1)
	{
		err(1, "Failed to bind socket");
	}

	if (chmod(opts.socket, PERMS) != 0)
	{
		err(1, "Failed to set socket permissions");
	}

	if (listen(sock_d, 5) == -1) // "5 is way more than enough"
	{
		err(1, "Failed to set socket to listening mode");
	}

	// set up poll() (not select())
	pcap_fd = pcap_get_selectable_fd(opts.l_handle);
	if (pcap_fd == PCAP_ERROR)
	{
		err(1, "Failed to get pcap selectable fd");
	}

	struct pollfd fds[POLL_N];
	memset(fds, 0, sizeof(fds));
	fds[0].fd = sock_d;
	fds[0].events = POLLIN;
	fds[1].fd = pcap_fd;
	fds[1].events = POLLIN;

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
				warn("poll() timed out or failed, retrying");
			continue;
		}

		if (fds[0].revents & POLLIN)
		{
			socklen_t size = sizeof(remote);
			sock_v = accept(sock_d
					, (struct sockaddr*)&remote
					, &size);

			if (sock_v == -1)
			{
				warn("Parent's accept() failed, retrying");
				continue;
			}

			child = fork();
			if (child < 0)
			{
				warn("Failed to fork(), retrying");
				continue;
			}
			else if (child == 0)
			{
				handle_con(sock_d, sock_v, &head);
				goto end;
			}

			close(sock_v);
		}

		if (fds[1].revents & POLLIN)
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
					warn
					("Packet buffer timeout expired.");
					gettimeofday(&now, NULL);
					break;
				case 1:
				{
					addrss = get_addrss(opts.l_handle,
							frame, header);

					// zero IP if not in the set subnet
					// or use the host's subnet
					subnet_filter   ( addrss.latest
							? addrss.ipv6
							: addrss.ipv4
					, opts.cidr	? &opts.subnet
							: &opts.host.subnet
					, addrss.latest);

					// go again if extraction failed
					// mac and a timeval are required
					if (!addrss_valid(&addrss)) continue;

					if (verbosity > 4)
					{
						print_mac(addrss.mac);
						print_ip( addrss.latest
							? addrss.ipv6
							: addrss.ipv4
							, addrss.latest);
					}

					addrss_list_add(&head, &addrss);

					// use arrival time to be consistent
					// regardless of pcap to_ms
					now = addrss.latest
						? addrss.ipv6_t
						: addrss.ipv4_t;
					break;
				}
				default:
					warn("Unexpected return value "
						"from pcap_next_ex: %d",
						result);
					continue;
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

	close(sock_d);
	remove(opts.socket);
end:
	for (struct Addrss* tmp; head != NULL;)
	{
		tmp = head;
		head = head->next;
		free(tmp);
	}
	if (child) fprintf(stderr, "\nStopped by:\t\t");
	switch (sig)
	{
		case SIGINT:
			fprintf(stderr, "SIGINT");
			break;
		case SIGTERM:
			fprintf(stderr, "SIGTERM");
			break;
	}
	if (child) printf("\n");

// and the stuff that's used by the header
end_header:

	if (opts.l_handle) pcap_close(opts.l_handle);
	if (opts.s_handle) pcap_close(opts.s_handle);
	free(opts.print_filename);
	free(opts.socket);
	if (opts.l_dev) free(opts.l_dev);
	if (opts.s_dev != opts.l_dev) free(opts.s_dev);
	return 0;
}

int clar_cat(int argc, char* argv[])
{
	int s, t, len;
	struct sockaddr_un remote;
	char str[100];

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	{
		err(1, "Failed to create socket");
	}

	remote.sun_family = AF_UNIX;
	if (argc > 1) strcpy(remote.sun_path, argv[1]);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1)
	{
		err(1, "Failed to connect to socket");
	}

	while ((t=recv(s, str, sizeof(str), 0)) > 0)
	{
		if ( -1 == write(STDOUT_FILENO, str, t))
		{
			err(1, "Failed to write to socket, try again?");
		}
	}

	close(s);
	return 0;
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
		// send out the list
		for (struct Addrss** current = head;
				*current != NULL;
				current = &((*current)->next))
		{
			char* string;
			if (asprint_clar(&string, *current) == -1)
			{
				close(sock_v);
				free(string);
				warn("Broke output");
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
	printf("Clarissa keeps a list of all connected devices on a network.\n");
	printf("It attempts to keep it as complete and up to date as possible.\n\n");
	printf("Defaults: Interface = first, listen = Interface, Timeout = 5s, Nags = 4, interval = Timeout / Nags, Promiscuous = 0, Verbosity = 0, subnet = Interface's IPv4 subnet, output file = /tmp/clar_[dev]_[subnet]-[mask], file output interval = timeout / 2\n");

	print_opts();
}

void print_opts()
{
	printf("\n%s\n", VERSION);
	printf("\nOptions:\nLong\t\tShort\n\n");
	printf("--help\t\t-h\n\tshow the help message\n");
	printf("--header\t-H\n\tshow the Header and exit\n");
	printf("--verbose\t-v\n\tincrease verbosity (shows 0 = err & warn < MAC < IP < chatty < debug < vomit)\n");
	printf("--version\t-V\n\tshow the Version\n");
	printf("--quiet\t\t-q\n\tQuiet, send out no packets (equivalent to -n 0)\n");
	printf("--promiscuous\t-p\n\tset the interface to Promiscuous mode\n");
	printf("--unbuffered\t-u\n\tdon't buffer packets (use immediate mode)\n");
	printf("\nRequiring an argument:\n\n");
	printf("--interface\t-I\n\tset the primary Interface\n");
	printf("--listen\t-l\n\tset the Listening interface\n");
	printf("--interval\t-i\n\tset the interval (in milliseconds)\n");
	printf("--nags\t\t-n\n\tset the number of times to \"Nag\" a target\n");
	printf("--timeout\t-t\n\tset the Timeout for an entry (wait time for nags in ms)\n");
	printf("--subnet\t-s\n\tget a Subnet to filter by (in CIDR notation)\n");
	printf("--file\t\t-f\n\tFile input (pcap file, works with - (stdin))\n");
	printf("--output_file\t-o\n\tset the output filename\n");
	printf("--output_interval -O\n\tset the Output interval\n");
}

void handle_opts(int argc, char* argv[], struct Opts* opts)
{
	// defaults
	opts->timeout 	= 5000000;
	opts->nags 	= 4;
	opts->run	= true;
	opts->immediate	= false;
	verbosity 	= 0;

	// local helpers
	bool version	= false;
	bool nags_set 	= false;
	char* auto_dev	= NULL;
	char* filename	= NULL;

	int opt;

	static struct option long_options[] =
		{
			{"version",		no_argument, 0,		'V'},
			{"verbose",		no_argument, 0, 	'v'},
			{"help",		no_argument, 0,		'h'},
			{"header",		no_argument, 0,		'H'},
			{"promiscuous",		no_argument, 0,		'p'},
			{"quiet",		no_argument, 0,		'q'},
			{"unbuffered",		no_argument, 0,		'u'},
			{"listen",		required_argument, 0,	'l'},
			{"interface",		required_argument, 0,	'I'},
			{"interval",		required_argument, 0,	'i'},
			{"nags", 		required_argument, 0,	'n'},
			{"timeout", 		required_argument, 0,	't'},
			{"subnet",		required_argument, 0,	's'},
			{"file", 		required_argument, 0,	'f'},
			{"output_file", 	required_argument, 0,	'o'},
			{"output_interval",	required_argument, 0,	'O'},
			{"socket",		required_argument, 0,	'S'}
		};
	int option_index = 0;
	while ((opt = getopt_long(argc, argv, "S:uHVvi:pn:l:t:qf:I:s:ho:O:",
				long_options, &option_index)) != -1)
	{
		switch (opt)
		{
			case 'S':
				// save socket path name
				if (asprintf(&opts->socket, "%s", optarg) == -1)
				{
					err(1, "Failed to save given socket path name");
				}
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
			case 'p':
				opts->promiscuous = true;
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
					err(1, "Failed to save given listening interface name");
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
					err(1, "Failed to save given file name");
				}
				break;
			case 'I':
				// get the sending interface
				if (asprintf(&opts->s_dev, "%s", optarg) == -1)
				{
					err(1, "Failed to save given sending interface name");
				}
				break;
			case 's':
				if (opts->cidr)
				{
					err(1,
				"Multiple subnets currently not supported");
				}
				// parse provided CIDR notation
				if (!get_cidr(&opts->subnet, optarg))
				{
					err(1, "Failed to parse CIDR");
				}
				else
				{
					if (verbosity > 1)
					{
						printf("subset ip:\t\t");
						// subnet.ip is v6 or mapped v4
						print_ip(opts->subnet.ip, true);
						printf("subset mask:\t\t%d\n",
							opts->subnet.mask);
					}
					opts->cidr += 1;
				}
				break;
			case 'h':
				help();
				exit(0);
			case 'o':
				opts->print_filename = optarg;
				break;
			case 'O':
				opts->print_interval = atoi(optarg) * 1000;
				if (opts->print_interval < 0) {
					warn("Failed to parse print interval");
				}
				break;
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
		warn("Listening on loopback currently not supported"
		", falling back on something else.");
		free(opts->l_dev);
		opts->l_dev = NULL;
	}

	// can't send to the "any" interface
	// set to null to allow fallback to auto_dev
	if (opts->s_dev && !strncmp(opts->s_dev, "any", 3))
	{
		warn("Sending to \"any\" currently not supported"
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
			err(1, "Failed to find an interface\n");
		}

		if (devs->description != NULL && verbosity > 2)
		{
			printf("%s\n", devs->description);
		}

		if (asprintf(&auto_dev, "%s", devs->name) == -1)
		{
			err(1, "Failed to save found listen interface name");
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
				err(1, "Failed to write s_dev to l_dev");
			}
		}
		else
		{
			if (asprintf(&opts->l_dev, "%s", auto_dev)
				== -1)
			{
				err(1, "Failed to write auto_dev to l_dev");
			}
		}
	}

	// fall back on auto_dev
	if (!opts->s_dev)
	{
		if (asprintf(&opts->s_dev, "%s", auto_dev) == -1)
		{
			err(1, "Failed to save auto_dev to s_dev");
		}
	}

	// assert everything's set up
	// TODO, support listening from file and sending to stdout or file
	// this would involve no devices...
	if (!(opts->l_dev && opts->s_dev))
	{
		err(1, "Failed to set up device(s)");
	}

	// make l_handle
	if (!filename)
	{
		opts->l_handle = pcap_create(opts->l_dev,
			opts->errbuf);
		if (opts->l_handle == NULL)
		{
			err(1, "pcap failed to create l_handle: %s",
				opts->errbuf);
		}

		// CAPLEN is probably 74
		if (pcap_set_snaplen(opts->l_handle, CAPLEN))
		{
			warn("Failed to set snapshot length");
		}

		if (pcap_set_promisc(opts->l_handle,
			opts->promiscuous))
		{
			warn("Failed to set promiscuous mode");
		}

		// timeout shouldn't have an effect if immediate
		// pcap timeout = half the interval (in milliseconds)
		if (pcap_set_timeout(opts->l_handle,
			opts->interval / 2000))
		{
			warn("Failed to set packet buffer timeout");
		}

		if (pcap_set_immediate_mode
			(opts->l_handle, opts->immediate))
		{
			warn("Failed to set immediate mode");
		}

		int result = pcap_activate(opts->l_handle);
		switch (result)
		{
			// warnings
			case PCAP_WARNING_PROMISC_NOTSUP:
				pcap_perror
				(opts->l_handle, "Activation: ");
				warn
				("promiscuous mode not supported");
				break;
			case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
				warn("set timestamp not supported");
				break;
			case PCAP_WARNING:
				pcap_perror
				(opts->l_handle, "Activation: ");
				break;
			// errors
			case PCAP_ERROR_ACTIVATED:
				err(1, "l_handle already active");
			case PCAP_ERROR_NO_SUCH_DEVICE:
				pcap_perror
				(opts->l_handle, "Activation: ");
				err(1, "no such capture source");
			case PCAP_ERROR_PERM_DENIED:
				pcap_perror
				(opts->l_handle, "Activation: ");
				err
				(1, "no permission to open source");
			case PCAP_ERROR_PROMISC_PERM_DENIED:
				err
				(1, "no permission for promiscuous");
			case PCAP_ERROR_RFMON_NOTSUP:
				err(1, "can't use monitor mode");
			case PCAP_ERROR_IFACE_NOT_UP:
				err(1, "capture source is not up");
			case PCAP_ERROR:
				pcap_perror
				(opts->l_handle, "Activation: ");
		}
	}

	// separate sending interface
	if (opts->nags)
	{
		opts->s_handle = pcap_open_live(opts->s_dev, 0, 0, 0,
			opts->errbuf);
		if (opts->s_handle == NULL)
		{
			err(1, "pcap failed to create s_handle: %s",
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

	// print_filename needs host.subnet
	if (!opts->print_filename)
	{
		char* ip;
		// subnet.ip is IPv6 or mapped v4
		asprint_ip(&ip, opts->host.subnet.ip, true);
		if (asprintf(&opts->print_filename
			// output to current directory (not removed)
			// if reading from file
			, !filename ? "/tmp/clar_%s_%s-%i"
			: "clar_parsed_%s"
			, filename ? filename : opts->l_dev
			, ip
			, opts->host.subnet.mask - 96) == -1)
		{
			err(1, "Failed to set the output filename");
		}
		free(ip);
	}
	else
	{
		if (asprintf(&opts->print_filename, "%s", opts->print_filename) == -1)
		{
			err(1, "Failed to set the output filename");
		}
	}

	if (!opts->socket)
	{
		char* ip;
		// subnet.ip is IPv4 or mapped v4
		asprint_ip(&ip, opts->host.subnet.ip, true);
		if (asprintf(&opts->socket, "/run/clar/%s_%s-%i", opts->l_dev
				, ip, opts->host.subnet.mask - 96) == -1)
		{
			err(1, "Failed to set the output socket path name");
		}
		free(ip);
	}

	free(auto_dev);
}

void print_header(const struct Opts* opts)
{
	if (!verbosity)
		fprintf(stderr, "Verbosity:\t%d\n\n", verbosity);
	if (!opts->l_dev) printf("Using file input\n\n");
	if (verbosity && opts->s_dev)
	{
		// host block
		printf("Listen interface:\t%s\n", opts->l_dev);
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
		if (opts->promiscuous) printf("Promiscuous\n");
		if (opts->immediate) printf("Unbuffered\n");
		if (!opts->nags) printf("Quiet\n");
		if (opts->promiscuous || opts->immediate
			|| !opts->nags)
		{
			printf("\n");
		}

		if (verbosity > 1)
		{
			// subnet block,
			// mask minus 96 as this is mapped IPv4
			char* ip;
			// subnet.ip is IPv6 or mapped v4
			asprint_ip(&ip, opts->host.subnet.ip, true);
			printf("Host IPv4 subnet:\t%s/%d\n",
				ip, opts->host.subnet.mask - 96);
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
				if (opts->print_interval)
				{
					printf("Output filename:\t%s\n", opts->print_filename);
					printf("Output interval:\t%dms\n",opts->print_interval / 1000);
				}
				printf("Output socket:\t%s\n", opts->socket);
				printf("\n");
			}
		}
	}
}
