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
	addrss.link_type = pcap_datalink(handle);
        switch (addrss.link_type)
        {
                // doesn't match offsets in dsniff/pcaputil.c
                case DLT_EN10MB:

                        addrss.offset += 14;

			// get the source MAC address
			memcpy(&addrss.mac, &frame[addrss.offset], 6);

                        // skip to payload
                        addrss.offset += 8;

                        // set offset based on payload type
                        switch (get_frame_type(frame, &addrss))
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

                                default:
                                        warn ("unsupported ethernet type\n");
					exit(1);
                        }

                        return addrss;

		case DLT_LINUX_SLL:

			warn ("\"any\" device not yet supported\n");
			exit(1);

                // TODO, 802.11, only get this link type in monitor mode...

                default:
                        warn ("unsupported link type\n");
			exit(1);
        }

        exit(1);
}


// return frame type for ethernet 802.11 and adjust offset in struct addrss
int get_frame_type(const uint8_t* frame, struct Addrss* addrss)
{
	// TODO

	// TODO, account for 802.1Q

        return 0;
}

// update the list (indicated by start) with a new entry
int addrss_list_update(struct Addrss* start, struct Addrss* new_addrss)
{
	// go through list and see if the new MAC address occurs
	// if it occurs, swap out struct or values
	// while going over the list, check for timed out elements

	return 0;
}
