#include "main.h"

// keep track of all online MAC addresses (<=10s timout) on the LANs
int main (int argc, char *argv[])
{
	// pcap setup
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = NULL;
	struct pcap_pkthdr header;
	const uint8_t* frame;
	char* dev = NULL;
	struct Addrss* head = NULL;
	int opt;
	struct Netmask netmask;
	memset(&netmask, 0, sizeof(struct Netmask));

	while ((opt = getopt (argc, argv, "d:f:s:")) != -1)
	{
		switch (opt)
		{
			case 'd':
				dev = optarg;
				break;

			case 'f':
				// file has priority over device
				dev = NULL;
				handle = pcap_open_offline(optarg, errbuf);
				break;

			case 's':
				// parse provided CIDR notation
				if (!parse_cidr(optarg, &netmask))
				{
					warn("Failed to parse CIDR");
					exit(1);
				}
				break;
		}
	}

	// TODO, clean this up
	if (!dev && !handle)
	{
		dev = pcap_lookupdev(errbuf);
	}

	if (!handle)
	{
		handle = pcap_open_live(dev, 54, 1, 1000, errbuf);
		if (!handle)
		{
			warn
			("Couldn't open pcap source %s: %s\n", dev, errbuf);
			return -1;
		}
	}

	//printf("using device %s\n", dev);

/*
	printf("parsed CIDR netmask:\n");
	for (int i = 0; i < 16; i++)
	{
		if (i && !(i % 2))
		{
			putchar(':');
		}
		printf("%02x", netmask.ip[i]);
	}
	printf("/%d\n", netmask.mask);
*/

	// main loop
	// capture, extract and update list of addresses
	for (;;)
	{
		frame = pcap_next(handle, &header);
		if (!frame) continue;

		// extract addresses and update the internal list
		addrss_list_update(&head, get_addrss(handle, frame, &header));

		// TODO, once every INTERVAL, check the entire list?

		// TODO, TEMPORARY, once a second output the list

		// maybe only check the full list at output?
	}


	pcap_close(handle);
	return 0;

}
