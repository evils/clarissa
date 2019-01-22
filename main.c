#include "main.h"

// keep track of all online MAC addresses (<=10s timout) on the LANs
int main (int argc, char *argv[])
{
	// pcap setup
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr header;
	const uint8_t* packet;
	//char* dev = pcap_lookupdev(errbuf);
	char* dev = "any";

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
			packet = pcap_next(handle, &header);
		}
		while (header.len < header.caplen);

		// TEMPORARY, output the MAC address
		int offset = 6;
		for (int byte = offset; byte <=(offset+4); byte++)
		{
			printf("%02x:", packet[byte]);
			if (byte >=(offset+4))
			{
				printf("%02x\n", packet[byte+1]);
			}
		}

		// update internal list
		/*
		// extract addresses and update the list
		addrss_list_update(get_addresses(&frame, &header));

		*/

		// TODO, TEMPORARY, once a second output the list


	}


	pcap_close(handle);
	return 0;

}
