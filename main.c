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

	// process options
	int opt;
	while ((opt = getopt (argc, argv, "l:n:t:q::i:f:s:")) != -1)
	{
		switch (opt)
		{
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
				// parse provided CIDR notation
				if (!parse_cidr(optarg, &subnet))
				{
					warn("Failed to parse CIDR");
					exit(1);
				}
				break;
		}
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
		handle = pcap_open_live(dev, 74, 1, 1000, errbuf);
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
	// TODO, fill in host with host machine's MAC and IP (v4 and v6)

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
