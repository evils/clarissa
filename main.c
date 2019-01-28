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
	//char* dev = "any";
	struct Addrss* head = NULL;

	handle = pcap_open_live(dev, 54, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}

	// TODO, start the list, make the first Addrss struct with host ID

	// main loop
	// capture, extract and update list of addresses
	for (;;)
	{
		do
		{
			frame = pcap_next(handle, &header);
		}
		while (header.len < header.caplen);

		// extract addresses and update the internal list
		addrss_list_update(&head, get_addrss(handle, frame, &header));

		// TODO, TEMPORARY, once a second output the list
	}


	pcap_close(handle);
	return 0;

}
