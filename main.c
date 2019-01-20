#include "main.h"

// keep track of all online MAC addresses (<=10s timout) on the LANs
int main (int argc, char *argv[])
{
	// pcap setup
	char* dev, errbuf[PCAP_ERRBUF_SIZE];
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return 2;
	}
	printf("Device: %s\n", dev);

	pcap_t *handle;
	handle = pcap_open_live(dev, 54, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}
	printf ("Device opened.");

	// TODO, more setup


	// output file setup
	// TODO


	// loop to capture, extract and update list of, MAC and IP addresses?
	// TODO



}
