#include "main.h"

// keep track of all online MAC addresses (<=10s timeout) on the LANs
int main (int argc, char *argv[])
{
	// pcap setup
	// errbuff, handle and dev are in the opts struct
	struct pcap_pkthdr header;
	const uint8_t* frame;

	// clarissa setup
	// more in the opts struct
	struct Addrss* head = NULL;
	struct timeval now;
	struct timeval last_print;
	struct timeval checked;

	gettimeofday(&checked, NULL);
	last_print = checked;

	// options setup
	struct Opts opts;
	memset(&opts, 0, sizeof(opts));

	handle_opts(argc, argv, &opts);


	// get the host ID
	get_mac(opts.host.mac, opts.dev);
	get_ipv4(opts.host.ipv4, opts.dev);
	// TODO, get_ipv6(opts.host.ipv6, dev);

	// startup header
	if (!verbosity) printf("Verbosity: %d\n", verbosity);
	else
	{
		printf("Host MAC address:\t");
		print_mac(opts.host.mac);
		if (opts.promiscuous) printf("Promiscuous\n");
		if (opts.nags == 0) printf("Quiet\n");
		if (verbosity > 2)
		{
			printf("Timeout:\t\t%dms\n", opts.timeout / 1000);
			if (opts.nags) printf("Nags:\t\t\t%d\n", opts.nags);
			printf("Interval:\t\t%dms\n", opts.interval / 1000);
		}
	}
	printf("\n");

	// main loop
	// capture, extract and update list of addresses
	for (;;)
	{
		// get a frame
		frame = pcap_next(opts.handle, &header);
		if (!frame) continue;

		// extract addresses and update the internal list
		struct Addrss addrss =
			get_addrss(opts.handle, frame, &header);

		// zero IP if it's not in the provided subnet
		subnet_check(addrss.ip, &opts.subnet);

		if (verbosity > 4)
		{
			print_mac(addrss.mac);
			print_ip(addrss.ip);
		}

		// move addrss to front of list
		addrss_list_add(&head, &addrss);

		gettimeofday(&now, NULL);
		if (usec_diff(&now, &checked) > opts.interval)
		{
			gettimeofday(&checked, NULL);

			// cull those that have been nagged enough
			addrss_list_cull
				(&head, &addrss.header.ts, opts.timeout,
					opts.nags);

			// and nag the survivors
			addrss_list_nag
				(&head, &addrss.header.ts, opts.timeout,
					&opts);
		}

		// TEMPORARY, update a file with the list
		if (usec_diff(&now, &last_print) > opts.print_interval) {
			last_print = now;
			dump_state(	opts.print_filename
					? opts.print_filename
					: "/tmp/clarissa_list"
					, head);
		}
		// maybe only check the full list at output?
	}

	pcap_close(opts.handle);
	return 0;

}

// print help header and options
void help()
{
	printf("Clarissa keeps a list of MAC and IP addresses of packets seen on the network.\n");
	printf("It attempts to be as complete and up to date as possible.\n\n");
	printf("Defaults: Timeout = 2s, Nags = 3, Interval = Timeout / Nags, Promiscuous = 0, Verbosity = 0, output file = /temp/clarissa_list, file output interval = timeout * \u03D5\n");

	print_opts();
}

void print_opts()
{
	printf("\nOptions: (those with * require an argument)\n\n");
	printf(" -f  *  File input (pcap file (tcpdump/wireshark), works with - (stdin))\n");
	printf(" -h     Help, show the help message\n");
	printf(" -i  *  set Interface used (can currently only use 1 at a time)\n");
	printf(" -l  *  set the intervaL (in milliseconds)\n");
	printf(" -n  *  Number of times to \"Nag\" a target (-n 0 is equivalent to -q)\n");
	printf(" -p     enable Promiscuous mode\n");
	printf(" -q     Quiet, send out no packets\n");
	printf(" -s  *  get a Subnet in CIDR notation (currently not used)\n");
	printf(" -t  *  set the Timeout for an entry (wait time for nags) (in milliseconds)\n");
	printf(" -v     increase Verbosity\n\t(shows 0 = errors & warn < MAC < IP < chatty < debug < vomit)\n");
	printf(" -o  *  set output filename\n");
	printf(" -O  *  set file Output interval\n");
	printf("\n");
}

void handle_opts(int argc, char* argv[], struct Opts* opts)
{
	// clarissa stuff
	opts->timeout = 2000000;
	opts->nags = 3;
	verbosity = 0;

	int opt;
	while ((opt = getopt (argc, argv, "vpl:n:t:qf:i:s:h::o:O:")) != -1)
	{
		switch (opt)
		{
			case 'v':
				verbosity++;
				break;
			case 'p':
				// get promiscuous mode
				opts->promiscuous = 1;
				break;
			case 'l':
				// get interval in ms
				opts->interval = (atoi(optarg) * 1000);
				break;
			case 'n':
				// get number times to nag a MAC
				opts->nags = atoi(optarg);
				break;
			case 't':
				// get timeout in ms
				opts->timeout = (atoi(optarg) * 1000);
				break;
			case 'q':
				// quiet, may be redundant
				opts->nags = 0;
				break;
			case 'f':
				// file has priority over device
				opts->dev = NULL;
				opts->nags = 0;
				opts->handle = pcap_open_offline
						(optarg, opts->errbuf);
				break;
			case 'i':
				// get the interface
				opts->dev = optarg;
				break;
			case 's':
				if (opts->parsed)
				{
					warn
				("Multiple subnets currently not supported");
					exit(1);
				}
				// parse provided CIDR notation
				if (!parse_cidr(optarg, &opts->subnet))
				{
					warn("Failed to parse CIDR");
					exit(1);
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
					opts->parsed = 1;
				}
				break;
			case 'o':
				opts->print_filename = optarg;
				break;
			case 'O':
				opts->print_interval = atoi(optarg) * 1000;
				if (opts->print_interval < 0) {
					warn("Failed to parse print interval");
				}
				break;
			case 'h':
				help();
				exit(0);
			default:
				// usage
				print_opts();
				exit(1);
		}
	}

	if (!opts->interval)
	{
		opts->interval =
			opts->timeout / (opts->nags ? opts->nags : 1);
	}

	if (!opts->print_interval)
	{
		// TODO, find a coprime?
		opts->print_interval = opts->timeout * 1.618;
	}

	// TODO, clean this up?
	if (!opts->dev && !opts->handle)
	{
		opts->dev = pcap_lookupdev(opts->errbuf);
	}

	if (!opts->handle)
	{
		opts->handle = pcap_open_live
				(opts->dev, 74, opts->promiscuous, 1000,
					opts->errbuf);
		if (!opts->handle)
		{
			warn
			("Couldn't open pcap source %s: %s\n",
				opts->dev, opts->errbuf);
			exit(1);
		}
	}
}
