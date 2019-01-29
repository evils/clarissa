#include "main.h"

// keep track of all online MAC addresses (<=10s timout) on the LANs
int main (int argc, char *argv[])
{
	// pcap setup
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	struct pcap_pkthdr header;
	const uint8_t* frame;
	char* dev = pcap_lookupdev(errbuf);
	struct Addrss* head = NULL;

/*
	if (filepath)
	{
		handle = pcap_open_offline(filepath, errbuf);
	}
	else
*/
	handle = pcap_open_live(dev, 54, 1, 1000, errbuf);
	if (handle == NULL)
	{
		warn
		("Couldn't open pcap source %s: %s\n", dev, errbuf);
		return -1;
	}

	// TODO, start the list, make the first Addrss struct with host ID

	// main loop
	// capture, extract and update list of addresses
	for (;;)
	{
		frame = pcap_next(handle, &header);
		if (frame == NULL) continue;

		// extract addresses and update the internal list
		addrss_list_update(&head, get_addrss(handle, frame, &header));

		// TODO, TEMPORARY, once a second output the list
	}


	pcap_close(handle);
	return 0;

}
