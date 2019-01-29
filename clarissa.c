#include "clarissa.h"

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
                case DLT_EN10MB:

			// preamble and start of frame delimiter not included

			// skip to source MAC address and store it
			frame += 6;
			memcpy(addrss.mac, frame, 6);

			// skip to metadata and get IP address
			frame += 6;
			get_eth_ip(&frame, &addrss);

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

int get_eth_ip(const uint8_t** frame, struct Addrss* addrss)
{
	switch (get_eth_protocol(frame))
	{
		case IPv4:

			// map IPv4 onto IPv6 address
			memset(&addrss->ip, 0, 10);
			memset(&addrss->ip[10], 1, 2);
			memcpy(&addrss->ip[12], *frame+14, 4);

			return 0;

		case ARP:

			// map IPv4 onto IPv6 address
			memset(&addrss->ip, 0, 10);
			memset(&addrss->ip[10], 1, 2);
			memcpy(&addrss->ip[12], *frame+16, 4);
			return 0;

		case IPv6:

			// copy IPv6 address to addrss
			memcpy(&addrss->ip, *frame+10, 16);
			return 0;

		case ETH_SIZE:
			// TODO, determine payload type
			// and extract IP

			// continue without IP
			warn ("ETH_SIZE");
			return 0;

		default:
			warn
			("unsupported EtherType: 0x%04x\n",
			get_eth_protocol(frame));

			exit(1);
	}
}

// TODO, verify and/or clean up?
int get_eth_protocol(const uint8_t** frame)
{
	// sort out 802.1Q and ad
	dot1_extend(frame);

	// save ethtype/size
	uint16_t type = ((uint16_t)(**frame) << 8)
			| (uint16_t)(**frame+1);

	return type <= 1500 ? ETH_SIZE : type;
}

// shift the pointer for 802.1Q and 802.1ad fields
int dot1_extend(const uint8_t** frame)
{
	for (;;)
	{
		// get a uint16_t from the frame
		uint16_t type = ((uint16_t)(**frame) << 8)
				| (uint16_t)(**frame+1);
		switch (type)
		{
			case DOTQ:
			case DOTAD:
			case DOUBLETAG:
				*frame += 4;
			default:
				return 0;
		}
	}
}

// update the list with a new entry
int addrss_list_update(struct Addrss** head, struct Addrss new_addrss)
{
	struct Addrss** current;
	struct timeval now;
	int found = 0;

	// go through the list while keeping a pointer
	// to the previous pointer
	for (current = head; *current != NULL;
		current = &((*current)->next))
	{
top_of_loop:
		// check if this has the new MAC address
		if (!memcmp(&(*current)->mac, &new_addrss.mac, 6))
		{
			// update time and ip
			(*current)->cap_time = new_addrss.cap_time;
			if (ip_check((*current)->ip))
				memcpy((*current)->ip, new_addrss.ip, 16);

			found = 1;

			// move it to the start of the list
			if (current != head) {
				struct Addrss* move = *current;
				*current = (*current)->next;
				move->next = *head;
				*head = move;

				if (*current != NULL) {
					goto top_of_loop;
				} else {
					break;
				}
			}
		}

		// check if it's timed out
		gettimeofday(&now, NULL);

		if (usec_diff((*current)->cap_time, now) > TIMEOUT)
		{
			// remove if exceeded tries
			if ((*current)->tried >= TRIES)
			{
				// remove the struct from the list
				struct Addrss* discard = *current;
				*current = (*current)->next;
				free(discard);

				if (*current != NULL) {
					goto top_of_loop;
				} else {
					break;
				}
			}
			else
			{
				query((*current));
				// reset timeval to allow for response time
				(*current)->cap_time = now;
				(*current)->tried++;
			}
		}
	}

	// insert at start of the list
	if (!found)
	{
		struct Addrss *new_head = malloc(sizeof *new_head);
		*new_head = new_addrss;
		new_head->next = *head;
		*head = new_head;

		// temporary
		print_mac(&new_addrss);
	}
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

int print_ip(struct Addrss* addrss)
{
	// TODO, check for mapped IPv4 and print IPv4 or IPv6?
	// or just print the IPv6 with mapped IPv4 address?
	return 0;
}

// send something to the target MAC to see if it's online
int query(struct Addrss* addrss)
{
	// TODO, attempt to find an IP if none is set for the target?
	// send an ARP packet?
	return 0;
}

// check if an IPv6 or mapped IPv4 address is in the provided subnet(s)
int ip_check(uint8_t* ip)
{
	// TODO
	return 0;
}
