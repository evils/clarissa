#include "main.h"

int main (int argc, char *argv[])
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
	uint64_t count = 0;

	signal(SIGINT, &sig_handler);
	signal(SIGTERM, &sig_handler);

	// capture, extract and update list of addresses
	for (;!sig;)
	{
		int result = pcap_next_ex(opts.handle,
					&header, &frame);
		switch (result)
		{
			case -2:
				printf("End of savefile reached.\n");
				goto end;
			case -1:
				pcap_perror(opts.handle,
					"Reading packet: ");
				continue;
			case 0:
				warn
				("Packet buffer timeout expired.");
				gettimeofday(&now, NULL);
				break;
			case 1:
			{
				addrss = get_addrss(opts.handle,
						frame, header);

				// zero IP if not in the set subnet
				// or use the host's
				if (opts.cidr)
					subnet_filter(addrss.ip,
						&opts.subnet);
				else
					subnet_filter(addrss.ip,
					&opts.host.ipv4_subnet);

				if (verbosity > 4)
				{
					print_mac(addrss.mac);
					print_ip(addrss.ip);
				}

				addrss_list_add(&head, &addrss);

				// use arrival time to be consistent
				// regardless of pcap to_ms
				now = addrss.header.ts;
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
		if (usec_diff(&now, &last_print) > opts.print_interval) {
			last_print = now;
			dump_state(opts.print_filename, head);
		}
	}

	// stats footer
	if(verbosity)
	{
		struct pcap_stat ps = {0};
		if(!pcap_stats(opts.handle, &ps))
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

	for (struct Addrss* tmp; head != NULL;)
	{
		tmp = head;
		head = head->next;
		free(tmp);
	}
	remove(opts.print_filename);
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

// and the stuff that's used by the header
end_header:

	pcap_close(opts.handle);
	free(opts.print_filename);
	free(opts.dev);
	return 0;
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
	printf("Defaults: Interface = first, Timeout = 5s, Nags = 4, interval = Timeout / Nags, Promiscuous = 0, Verbosity = 0, subnet = interface's IPv4 subnet, output file = /tmp/clar_[dev]_[subnet]-[mask], file output interval = timeout / 2 \n");

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
	printf("--interface\t-I\n\tset the Interface used. If set to \"any\", -n 0 is forced\n");
	printf("--interval\t-i\n\tset the interval (in milliseconds)\n");
	printf("--nags\t\t-n\n\tset the number of times to \"Nag\" a target\n");
	printf("--timeout\t-t\n\tset the Timeout for an entry (wait time for nags in ms)\n");
	printf("--subnet\t-s\n\tget a Subnet to filter by (in CIDR notation)\n");
	printf("--file\t\t-f\n\tFile input (pcap file, works with - (stdin)), forces -n 0\n");
	printf("--output_file\t-o\n\tset the output filename\n");
	printf("--output_interval -O\n\tset the Output interval\n");
}

void handle_opts(int argc, char* argv[], struct Opts* opts)
{
	opts->timeout 	= 5000000;
	opts->nags 	= 4;
	opts->run	= 1;
	opts->immediate	= 0;
	verbosity 	= 0;
	int version	= 0;
	int nags_set 	= 0;

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
			{"interface",		required_argument, 0,	'I'},
			{"interval",		required_argument, 0,	'i'},
			{"nags", 		required_argument, 0,	'n'},
			{"timeout", 		required_argument, 0,	't'},
			{"subnet",		required_argument, 0,	's'},
			{"file", 		required_argument, 0,	'f'},
			{"output_file", 	required_argument, 0,	'o'},
			{"output_interval",	required_argument, 0,	'O'}
		};
	int option_index = 0;
	while ((opt = getopt_long(argc, argv, "uHVvi:pn:t:qf:I:s:ho:O:",
				long_options, &option_index)) != -1)
	{
		switch (opt)
		{
			case 'u':
				opts->immediate = 1;
				break;
			case 'H':
				opts->run = 0;
				break;
			case 'V':
				version = 1;
				break;
			case 'v':
				verbosity++;
				break;
			case 'i':
				// get interval in ms
				opts->interval = (atoi(optarg) * 1000);
				break;
			case 'p':
				opts->promiscuous = 1;
				break;
			case 'n':
				// get number times to nag an entry
				if (!nags_set)
				{
					opts->nags = atoi(optarg);
					nags_set = 1;
				}
				break;
			case 't':
				// get timeout in ms
				opts->timeout = (atoi(optarg) * 1000);
				break;
			case 'q':
				// quiet, may be redundant
				opts->nags = 0;
				nags_set = 1;
				break;
			case 'f':
				// file has priority over device
				opts->dev = NULL;
				if (!nags_set)
				{
					opts->nags = 0;
					nags_set = 2;
				}
				opts->handle = pcap_open_offline
						(optarg, opts->errbuf);
				break;
			case 'I':
				// get the interface
				if (asprintf(&opts->dev, "%s", optarg) == -1)
				{
					errx(1, "Failed to save given interface name");
				}
				if (!strcmp(opts->dev, "any"))
				{
					printf("using \"any\" device\n");
					// can't nag with "any" device
					opts->nags = 0;
					nags_set = 3;
				}
				break;
			case 's':
				if (opts->cidr)
				{
					errx(1,
				"Multiple subnets currently not supported");
				}
				// parse provided CIDR notation
				if (!get_cidr(&opts->subnet, optarg))
				{
					errx(1, "Failed to parse CIDR");
				}
				else
				{
					if (verbosity > 1)
					{
						printf("subset ip:\t\t");
						print_ip(opts->subnet.ip);
						printf("subset mask:\t\t%d\n",
							opts->subnet.mask);
					}
					opts->cidr = 1;
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

	if (version)
	{
		printf("Version:\t");
		if (verbosity || !opts->run) printf("\t");
		printf("%s\n", VERSION);
	}

	if (!opts->interval)
	{
		opts->interval =
			opts->timeout / (opts->nags ? opts->nags : 1);
	}

	if (!opts->print_interval)
	{
		// TODO, find a coprime?
		// this is not phase-locked with opts.interval?
		opts->print_interval = opts->timeout / 2;
	}

	// TODO, clean this up?
	if (!opts->dev && !opts->handle)
	{
		pcap_if_t* devs;
		if (pcap_findalldevs(&devs, opts->errbuf)
			|| devs == NULL)
		{
			err(1, "Failed to find a device\n");
		}

		if (devs->description != NULL && verbosity > 2)
		{
			printf("%s\n", devs->description);
		}

		if (asprintf(&opts->dev, "%s", devs->name) == -1)
		{
			errx(1, "Failed to save found interface name");
		}
		pcap_freealldevs(devs);
	}
	else if (nags_set == 1)
		printf("Recommended nags for file input is 0\n");
	char lo[] = "lo";
	if (opts->dev != NULL && !strncmp(opts->dev, lo, 2))
		errx(1, "loopback device currently not supported");

	if (!opts->handle)
	{
		opts->handle = pcap_create(opts->dev, opts->errbuf);
		if (opts->handle == NULL)
		{
			errx(1, "Failed to create pcap handle: %s",
				opts->errbuf);
		}

		// 74 = capture length
		if (pcap_set_snaplen(opts->handle, 74))
		{
			warn("Failed to set snapshot length");
		}

		if (pcap_set_promisc(opts->handle,
			opts->promiscuous))
		{
			warn("Failed to set promiscuous mode");
		}

		// timeout shouldn't have an effect if immediate
		// pcap timeout = half the interval (in milliseconds)
		if (pcap_set_timeout(opts->handle,
			opts->interval / 2000))
		{
			warn("Failed to set packet buffer timeout");
		}

		if (pcap_set_immediate_mode
			(opts->handle, opts->immediate))
		{
			warn("Failed to set immediate mode");
		}

		int result = pcap_activate(opts->handle);
		switch (result)
		{
			// warnings
			case PCAP_WARNING_PROMISC_NOTSUP:
				pcap_perror
				(opts->handle, "Activation: ");
				warn
				("promiscuous mode not supported");
				break;
			case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
				warn("set timestamp not supported");
				break;
			case PCAP_WARNING:
				pcap_perror
				(opts->handle, "Activation: ");
				break;
			// errors
			case PCAP_ERROR_ACTIVATED:
				errx(1, "handle already active");
			case PCAP_ERROR_NO_SUCH_DEVICE:
				pcap_perror
				(opts->handle, "Activation: ");
				errx(1, "no such capture source");
			case PCAP_ERROR_PERM_DENIED:
				pcap_perror
				(opts->handle, "Activation: ");
				errx
				(1, "no permission to open source");
			case PCAP_ERROR_PROMISC_PERM_DENIED:
				errx
				(1, "no permission for promiscuous");
			case PCAP_ERROR_RFMON_NOTSUP:
				errx(1, "can't use monitor mode");
			case PCAP_ERROR_IFACE_NOT_UP:
				errx(1, "capture source is not up");
			case PCAP_ERROR:
				pcap_perror
				(opts->handle, "Activation: ");
		}
	}

	// fill in the host ID
	get_if_mac(opts->host.mac, opts->dev);
	get_if_ipv4_subnet(&opts->host.ipv4_subnet, opts);
	get_if_ip(opts->host.ipv4, opts->dev, AF_INET, opts->errbuf);
	get_if_ip(opts->host.ipv6, opts->dev, AF_INET6,opts->errbuf);

	// print_filename needs host.mac
	if (!opts->print_filename)
	{
		char* ip;
		asprint_ip(&ip, opts->host.ipv4_subnet.ip);
		if (asprintf(&opts->print_filename,
			"/tmp/clar_%s_%s-%i", opts->dev, ip,
				opts->host.ipv4_subnet.mask - 96) == -1)
		{
			errx(1, "Failed to set the output filename");
		}
		free(ip);
	}
	else
	{
		if (asprintf(&opts->print_filename, "%s", opts->print_filename) == -1)
		{
			errx(1, "Failed to set the output filename");
		}
	}
}

void print_header(struct Opts* opts)
{
	if (!verbosity)
		fprintf(stderr, "Verbosity:\t%d\n\n", verbosity);
	if (!opts->dev) printf("Using file input\n\n");
	if (verbosity && opts->dev)
	{
		// host block
		printf("Host interface:\t\t%s\n", opts->dev);
		printf("Host MAC address:\t");
		print_mac(opts->host.mac);
		if (verbosity > 1)
		{
			printf("Host IPv4 address:\t");
			print_ip(opts->host.ipv4);
			printf("Host IPv6 address:\t");
			print_ip(opts->host.ipv6);
		}
		printf("\n");

		// mode block
		if (opts->promiscuous) printf("Promiscuous\n");
		if (opts->immediate) printf("Unbuffered\n");
		if (!opts->nags) printf("Quiet\n");
		if (opts->promiscuous || opts->immediate
			|| !opts-> nags)
		{
			printf("\n");
		}

		if (verbosity > 1)
		{
			// subnet block,
			// mask minus 96 as this is mapped IPv4
			char* ip;
			asprint_ip(&ip, opts->host.ipv4_subnet.ip);
			printf("Host IPv4 subnet:\t%s/%d\n",
				ip, opts->host.ipv4_subnet.mask - 96);
			free(ip);
			printf("\n");

			if (verbosity > 2)
			{
				// options block
				printf("Timeout:\t\t%dms\n",
					opts->timeout / 1000);
				if (opts->nags) printf("Nags:\t\t\t%d\n",
					opts->nags);
				printf("Interval:\t\t%dms\n",
					opts->interval / 1000);
				printf("\n");
				printf("Output filename:\t%s\n",
					opts->print_filename);
				printf("Output interval:\t%dms\n",
					opts->print_interval / 1000);
				printf("\n");
			}
		}
	}
}
