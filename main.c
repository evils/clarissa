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
	struct timeval now, last_print, checked;

	gettimeofday(&checked, NULL);
	last_print = checked;

	// options setup
	struct Opts opts;

	memset(&opts, 0, sizeof(opts));
	handle_opts(argc, argv, &opts);

	// get the host ID
	get_if_mac(opts.host.mac, opts.dev);
	get_if_ipv4_subnet(&opts.host.ipv4_subnet, &opts);
	get_if_ip(opts.host.ipv4, opts.dev, AF_INET, opts.errbuf);
	get_if_ip(opts.host.ipv6, opts.dev, AF_INET6, opts.errbuf);

	// startup header
	print_header(&opts);

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
		if (opts.cidr) subnet_check(addrss.ip, &opts.subnet);
		else subnet_check(addrss.ip, &opts.host.ipv4_subnet);

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
			dump_state(opts.print_filename, head);
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
	printf("Defaults: Timeout = 2s, Nags = 3, Interval = Timeout / Nags, Promiscuous = 0, Verbosity = 0, output file = /tmp/clarissa_list, file output interval = timeout * \u03D5\n");

	print_opts();
}

void print_opts()
{
	printf("\nOptions: (those with * require an argument)\n\n");
	printf(" -v     increase Verbosity\n\t(shows 0 = errors & warn < MAC < IP < chatty < debug < vomit)\n");
	printf(" -h     show the Help message\n");
	printf(" -p     use Promiscuous mode\n");
	printf(" -q     Quiet, send out no packets\n");
	printf(" -I  *  set the Interface used (only one per instance)\n");
	printf(" -i  *  set the interval (in milliseconds)\n");
	printf(" -n  *  set times to \"Nag\" a target (-n 0 is equivalent to -q)\n");
	printf(" -t  *  set the Timeout for an entry (wait time for nags) (in milliseconds)\n");
	printf(" -s  *  get a Subnet to filter by, in CIDR notation\n");
	printf(" -f  *  File input (pcap file (tcpdump/wireshark), works with - (stdin))\n");
	printf(" -o  *  set output filename\n");
	printf(" -O  *  set file Output interval\n");
	printf("\n");
}

void handle_opts(int argc, char* argv[], struct Opts* opts)
{
	// clarissa stuff
	opts->timeout 	= 2000000;
	opts->nags 	= 3;
	verbosity 	= 0;
	int nags_set 	= 0;

	int opt;
	while ((opt = getopt (argc, argv, "vi:pn:t:qf:I:s:ho:O:")) != -1)
	{
		switch (opt)
		{
			case 'v':
				verbosity++;
				break;
			case 'i':
				// get interval in ms
				opts->interval = (atoi(optarg) * 1000);
				break;
			case 'p':
				// get promiscuous mode
				opts->promiscuous = 1;
				break;
			case 'n':
				// get number times to nag a MAC
				opts->nags = atoi(optarg);
				nags_set = 1;
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
				opts->dev = optarg;
				break;
			case 's':
				if (opts->cidr)
				{
					warn
				("Multiple subnets currently not supported");
					exit(1);
				}
				// parse provided CIDR notation
				if (!get_cidr(&opts->subnet, optarg))
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
	else if (nags_set == 1)
		printf("recommended nags for file input is 0\n");

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

	if (!opts->print_filename)
	{
		opts->print_filename = "/tmp/clarissa_list";
	}
}

void print_header(struct Opts* opts)
{
	if (!verbosity) printf("Verbosity:\t%d\n\n", verbosity);
	if (!opts->dev) printf("Using file input\n\n");
	else
	{
		// host block
		printf("Host interface:\t\t%s\n", opts->dev);
		printf("Host MAC address:\t");
		print_mac(opts->host.mac);
		printf("Host IPv4 address:\t");
		print_ip(opts->host.ipv4);
		printf("Host IPv6 address:\t");
		print_ip(opts->host.ipv6);
		printf("\n");

		// mode block
		if (opts->promiscuous) printf("Promiscuous\n");
		if (!opts->nags) printf("Quiet\n");
		if (opts->promiscuous || !opts-> nags) printf("\n");

		// further details
		if (verbosity > 2)
		{
			// subnet block
			printf("Host IPv4 subnet:\t");
			print_ip(opts->host.ipv4_subnet.ip);
			printf("Host IPv4 mask:\t\t%d\n",
			// minus 96 as long as this is IPv4
			opts->host.ipv4_subnet.mask - 96);
			printf("\n");

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
