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
	printf ("Device opened.\n");

	// main loop
	// capture, extract and update list of addresses
	for (;;)
	{
		packet = pcap_next(handle, &header);
		printf("Success, got %d saved %d\n"
			, header.caplen, header.len);

		printf("Link type ");
		int link_type = pcap_datalink(handle);
		switch (link_type)
		{
			case DLT_EN10MB:
				printf("DLT_EN10MB\n");
			break;

			case DLT_LINUX_SLL:
				printf("DLT_LINUX_SLL\n");
			break;

			case DLT_IEEE802_11:
				printf("DLT_IEEE802_11\n");
			break;

			default:
				printf("Unknown, %d\n", link_type);
		}

		// extract addresses
			// TODO also get receive timestamps?
		int offset = 6;
		printf("MAC ");
		for (int byte = offset; byte <=(offset+4); byte++)
		{
			printf("%02x:", packet[byte]);
			if (byte >=(offset+4))
			{
				printf("%02x\n", packet[byte+1]);
			}
		}

		// update internal list

		// remove MACs with "tries" > limit
		// query timed out MACs, increment "tries" counter

	}


	pcap_close(handle);
	return 0;

}
