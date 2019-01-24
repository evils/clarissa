#include "get_addresses.h"

// Save the source addresses and receive time from a packet in a struct.
struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header)
{
        struct Addrss addrss;
        memset(&addrss, 0, sizeof(addrss));

	addrss.cap_time = header->ts;

	// assume a packet is correct (discard len < caplen (54) ?)
        // an invalid MAC will be unreachable and get purged
        // check if the IP is in the right range later?

        // link type is separately stored metadata?
        switch (pcap_datalink(handle))
        {
                // doesn't match offsets in dsniff/pcaputil.c
                case DLT_EN10MB:

			// preamble and start of frame delimiter not included
			// skip destination MAC address
                        addrss.offset += 6;

			// get the source MAC address
			memcpy(&addrss.mac, &frame[addrss.offset], 6);

                        // skip to metadata
                        addrss.offset += 6;

                        // set offset based on payload protocol
                        switch (get_eth_protocol(frame, &addrss))
                        {
                                case IPv4:
                                        addrss.offset += 12;

					// map IPv4 onto IPv6 address
					memset(&addrss.ip, 0, 10);
					memset(&addrss.ip[10], 1, 2);
					memcpy(&addrss.ip[12],
						&frame[addrss.offset], 4);
                                        break;

                                case ARP:
                                        addrss.offset += 14;

					// map IPv4 onto IPv6 address
					memset(&addrss.ip, 0, 10);
					memset(&addrss.ip[10], 1, 2);
					memcpy(&addrss.ip[12],
						&frame[addrss.offset], 4);
                                        break;

                                case IPv6:
                                        addrss.offset += 8;

					// copy IPv6 address to addrss
					memcpy(&addrss.ip,
						&frame[addrss.offset], 16);
                                        break;

				case ETH_SIZE:
					// TODO, determine payload type
					// and extract IP

					// continue without IP
					break;

                                default:
                                        warn
					("unsupported ethernet type: %i\n",
					get_eth_protocol(frame, &addrss));
					exit(1);
                        }

                        return addrss;

		case DLT_LINUX_SLL:

			warn ("\"any\" device not yet supported\n");
			exit(1);

                // TODO, 802.11, only get this link type in monitor mode...

                default:
                        warn ("unsupported link type: %i\n",
				pcap_datalink(handle));
			exit(1);
        }

        exit(1);
}

// return payload type, adjust offset appropriately
// TODO, verify and/or clean up, sort out byte order?
int get_eth_protocol(const uint8_t* frame, struct Addrss* addrss)
{

	// sort out 802.1Q and ad
	dot1_extend(frame, addrss);

	// save ethtype/size
	uint16_t type = frame[addrss->offset];

	// 802.3 frame size
	if (type <= 1500)
	{
		addrss->offset += 2;
		return ETH_SIZE;
	}
	// EtherType
	switch (type)
	{
		case (IPv4):
			addrss->offset += 2;
			return IPv4;
		case (ARP):
			addrss->offset += 2;
			return ARP;
		case (IPv6):
			addrss->offset += 2;
			return IPv6;
	}

        return -1;
}

// extend the offset for 802.1Q and 802.1ad
int dot1_extend(const uint8_t* frame, struct Addrss* addrss)
{
	while
	((frame[addrss->offset] == DOTQ) || (frame[addrss->offset] == DOTAD
		|| frame[addrss->offset] == DOUBLETAG))
		addrss->offset += 4;
	return 0;
}

// update the list (indicated by start) with a new entry
int addrss_list_update(struct Addrss* head, struct Addrss new_addrss)
{
	// go through list and see if the new MAC address occurs
	// if it occurs, swap out struct or values
	// while going over the list, check for timed out elements

	return 0;
}

int print_mac(struct Addrss* addrss)
{
	for(int byte = 0; byte <= 4; byte++)
	{
		printf("%02x:", addrss->mac[byte]);
		if (byte >= 4)
		{
			printf("%02x\n", addrss->mac[byte+1]);
		}
	}
	return 0;
}
