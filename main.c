#include "main.h"

// keep track of all online MAC addresses (<=10s timout) on the LANs
int main (int argc, char *argv[])
{
	// pcap setup
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	struct pcap_pkthdr header;
	const uint8_t* frame;
	char* dev = NULL;
	struct Addrss* head = NULL;
	int opt;

	while ((opt = getopt (argc, argv, "d:f:")) != -1)
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
	}


	pcap_close(handle);
	return 0;

}
