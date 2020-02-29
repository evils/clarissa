#define _GNU_SOURCE
#include <err.h>	// errx
#include <stdio.h>	// printf
#include <stdint.h>	// uint8_t
#include <pcap.h>	// pcap_*

#include "get_hardware_address.h"	// get_hardware_address()

int is_zeros(const uint8_t* target, int count);

int main(int argc, char* argv[])
{
	uint8_t mac[6] = {0};
	char* dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (argc > 1)
	{
		if ((asprintf(&dev, "%s", argv[1]) == -1))
		{
			errx(1, "Failed to save given interface name");
		}
		printf("Trying interface:\t%s\n", dev);
	}
	else
	{
		pcap_if_t* devs;

		if (pcap_findalldevs(&devs, errbuf)
				|| devs == NULL)
		{
			errx(1, "Failed to find a device\n");
		}


		if (devs->description != NULL)
		{
			printf("Found description:\t%s\n", devs->description);
		}

		if (asprintf(&dev, "%s", devs->name) == -1)
		{
			errx(1, "Failed to save found interface name");
		}
		printf("Found interface:\t%s\n", dev);

		pcap_freealldevs(devs);
	}

	get_hardware_address(dev, mac);
	if (is_zeros(mac, sizeof(mac)))
	{
		errx(1, "Got an all zero MAC address\n"
		"      is that a valid interface?\n"
		"      and are you running this as root?"
		    );
	}

	printf("With MAC address:\t");
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	return 0;
}

int is_zeros(const uint8_t* target, int count)
{
        while (count--)
        {
                if (target[count]) return 0;
        }
        return 1;
}
