#include "main.h"

// keep track of all online MAC addresses (<=10s timout) on the LANs
int main (int argc, char *argv[])
{
	// pcap setup
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const uint8_t* frame;
	pcap_t* handle = NULL;
	char* dev = NULL;

	// clarissa setup
	struct Addrss* head = NULL;
	struct Subnet subnet;
	memset(&subnet, 0, sizeof(struct Subnet));
	struct timeval now;
	struct timeval checked;
	gettimeofday(&checked, NULL);
	int timeout = 2000000;
	int interval = 0;
	int nags = 3;
	int promiscuous = 0;
	verbosity = 0;
	int parsed = 0;

	// process options
	int opt;
	while ((opt = getopt (argc, argv, "v::p::l:n:t:q::i:f:s:h::")) != -1)
	{
		switch (opt)
		{
			case 'v':
				if (optarg) verbosity = atoi(optarg);
				else verbosity++;
				break;
			case 'p':
				// get promiscuous mode
				promiscuous = 1;
				break;
			case 'l':
				// get interval in ms
				interval = (atoi(optarg) * 1000);
				break;
			case 'n':
				// get number times to nag a MAC
				nags = atoi(optarg);
				break;
			case 't':
				// get timeout in ms
				timeout = (atoi(optarg) * 1000);
				break;
			case 'q':
				// quiet, may be redundant
				nags = 0;
				break;
			case 'i':
				// get the interface
				dev = optarg;
				break;
			case 'f':
				// file has priority over device
				dev = NULL;
				nags = 0;
				handle = pcap_open_offline(optarg, errbuf);
				break;
			case 's':
				if (parsed)
				{
					warn
				("Multiple subnets currently not supported");
					exit(1);
				}
				// parse provided CIDR notation
				if (!parse_cidr(optarg, &subnet))
				{
					warn("Failed to parse CIDR");
					exit(1);
				}
				else parsed = 1;
				break;
			case 'h':
				help();
				return 0;
			default:
				// usage
				print_opts();
				return -1;
		}
	}

	if (!parsed)
	{
		subnet.mask = 128;
	}

	if (!interval)
	{
		interval = timeout / (nags ? nags : 1);
	}

	// TODO, clean this up
	if (!dev && !handle)
	{
		dev = pcap_lookupdev(errbuf);
	}

	if (!handle)
	{
		handle = pcap_open_live(dev, 74, promiscuous, 1000, errbuf);
		if (!handle)
		{
			warn
			("Couldn't open pcap source %s: %s\n",
				dev, errbuf);
			return -1;
		}
	}

	// set up host ID
	struct Host host;
	memset(&host, 0, sizeof(host));
	get_mac(host.mac, dev);
	get_ipv4(host.ipv4, dev);
	// TODO, get_ipv6(host.ipv6, dev);

	// startup header
	if (!verbosity) printf("Verbosity: %d\n", verbosity);
	else
	{
		printf("Host MAC address:\t");
		print_mac(host.mac);
		if (promiscuous) printf("Promiscuous\n");
		if (nags == 0) printf("Quiet\n");
		if (verbosity > 3)
		{
			printf("Timeout:\t\t%dms\n", timeout / 1000);
			if (nags) printf("Nags:\t\t\t%d\n", nags);
			printf("Interval:\t\t%dms\n", interval / 1000);
		}
	}
	printf("\n");

	// main loop
	// capture, extract and update list of addresses
	for (;;)
	{
		// get a frame
		frame = pcap_next(handle, &header);
		if (!frame) continue;

		// extract addresses and update the internal list
		struct Addrss addrss =
			get_addrss(handle, frame, &header);

		// zero IP if it's not in the provided subnet
		subnet_check(addrss.ip, &subnet);

		// move addrss to front of list
		addrss_list_add(&head, &addrss);

		gettimeofday(&now, NULL);
		if (usec_diff(&now, &checked) > interval)
		{
			gettimeofday(&checked, NULL);

			// cull those that have been nagged enough
			addrss_list_cull
			(&head, &addrss.header.ts, timeout, nags);

			// and nag the survivors
			addrss_list_nag
			(&head, &addrss.header.ts, timeout, &host);
		}

		// TODO, TEMPORARY, once a second output the list

		// maybe only check the full list at output?
	}

	pcap_close(handle);
	return 0;

}

// print help header and options
int help()
{
	printf("Clarissa keeps a list of MAC and IP addresses of packets seen on the network.\n");
	printf("It attempts to be as complete and up to date as possible.\n\n");
	printf("Defaults: Timeout = 2s, Nags = 3, Interval = Timeout/Nags, Promiscuous = 0, Verbosity = 0\n");

	print_opts();

	return 0;
}

int print_opts()
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
	printf(" -v     set or increase Verbosity\n\t(shows 0 = errors & warn < MAC < IP < debug < vomit)\n");
	printf("\n");

	return 0;
}
