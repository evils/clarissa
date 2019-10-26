#define _GNU_SOURCE
#include <err.h>	// errx
#include <stdio.h>	// printf
#include <stdint.h>	// uint8_t
#include <pcap.h>	// pcap_*

#include "get_mac.h"	// get_mac()

int main(void)
{
	uint8_t mac[6] = {0};
	char* dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t* devs;
	if (pcap_findalldevs(&devs, errbuf)
		|| devs == NULL)
	{
		errx(1, "Failed to find a device\n");
	}

	if (devs->description != NULL)
	{
		printf("%s\n", devs->description);
	}

	if (asprintf(&dev, "%s", devs->name) == -1)
	{
		errx(1, "Failed to save found interface name");
	}
	pcap_freealldevs(devs);

	get_mac(dev, mac);
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	return 0;
}
