#include "clarissa.h"

// Save the source addresses and receive time from a packet in a struct.
struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header)
{
        struct Addrss addrss;
        memset(&addrss, 0, sizeof(struct Addrss));

	addrss.header = *header;

	// assume a packet is correct (discard len < caplen (74) ?)
        // an invalid MAC will be unreachable and get purged
        // check if the IP is in the right range later?

        // link type is separately stored metadata?
        switch (pcap_datalink(handle))
        {
                case DLT_EN10MB:

			// preamble and start of frame delimiter not included

			// skip to source MAC address and store it
			memcpy(addrss.mac, frame += 6, 6);

			// skip to metadata and get IP address
			if (!get_tag(frame+6, &addrss))
			{
                        return addrss;
			}
			else
			{
				warn ("failed to extract ethernet frame");
				exit(1);
			}

		case DLT_LINUX_SLL:

			warn ("\"any\" device not yet supported\n");
			exit(1);

		case DLT_IEEE802_11:

			warn ("WLAN is not yet supported\n");
			exit(1);

                default:
                        warn ("unsupported link type: %i\n",
				pcap_datalink(handle));
        }

        exit(1);
}

// get a VLAN tag from the frame and continue handling the frame
int get_tag(const uint8_t* frame, struct Addrss* addrss)
{
	uint16_t type = ((uint16_t)(frame[0]) << 8) | (uint16_t)(frame[1]);
	uint64_t frame_tag;
	switch (type)
	{
		case DOT1Q:
		case DOT1AD:
		case DOUBLETAG:
			frame_tag = ((uint64_t)frame[2] << 8)
				   + (uint64_t)frame[3];

			// pack the tag and increment the count
			addrss->tags += (frame_tag << (addrss->tags >> 60))
					+ ((uint64_t)1 << 60);

			addrss->header.caplen -= 4;

			// TODO, check if exceeded max tags?
			get_tag(frame + 4, addrss);

		default:
			addrss->header.caplen -= 2;
			return (get_eth_ip(frame + 2, addrss,
				type <= 1500 ? ETH_SIZE : type));
	}
}

int get_eth_ip(const uint8_t* frame, struct Addrss* addrss, uint16_t type)
{
	switch (type)
	{
		case IPv4:

			// map IPv4 onto IPv6 address
			memset(addrss->ip, 0, 10);
			memset(addrss->ip+10, 1, 2);
			memcpy(addrss->ip+12, frame+12, 4);
			break;

		case ARP:

			// map IPv4 onto IPv6 address
			memset(addrss->ip, 0, 10);
			memset(addrss->ip+10, 1, 2);
			memcpy(addrss->ip+12, frame+14, 4);
			break;

		case IPv6:

			// copy IPv6 address to addrss
			memcpy(addrss->ip, frame+8, 16);
			break;

		case ETH_SIZE:
			// TODO, determine payload type
			// and extract IP

			// continue without IP
			warn ("ETH_SIZE");
			break;

		case ARUBA_AP_BC:

			//warn ("Aruba Instant AP broadcast packet found");
			break;

		default:
			warn
			("unsupported EtherType: 0x%04x, from: v",
			type);
			print_mac(addrss->mac);
	}

	return 0;
}

// update the list with a new entry
int addrss_list_add(struct Addrss** head, struct Addrss* new_addrss)
{
	uint8_t zeros[16];
	memset(&zeros, 0, 16);
	int found = 0;

	// go through the list while keeping a pointer
	// to the previous pointer
	for (struct Addrss** current = head;
		*current != NULL;
		current = &((*current)->next))
	{
top_of_loop:
		// check if this has the new MAC address
		if (!memcmp((*current)->mac, new_addrss->mac, 6))
		{
			// update time and ip
			(*current)->header.ts = new_addrss->header.ts;
			(*current)->tried = 0;
			if (memcmp((*current)->ip, &zeros, 16))
				memcpy((*current)->ip, new_addrss->ip, 16);

			found = 1;

			// move it to the start of the list
			if (current != head) {
				struct Addrss* move = *current;
				*current = (*current)->next;
				move->next = *head;
				*head = move;

				if (*current != NULL)
				{
					goto top_of_loop;
				}
				else break;
			}
		}

	}

	// insert at start of the list
	if (!found)
	{
		struct Addrss *new_head = malloc(sizeof *new_head);
		*new_head = *new_addrss;
		new_head->next = *head;
		*head = new_head;

		// TEMPORARY output
		if (verbosity) print_mac(new_addrss->mac);
		if (verbosity > 1) print_ip(new_addrss->ip);
	}
	return 0;
}

// remove timed out elements that exceeded nags
int addrss_list_cull
(struct Addrss** head, struct timeval* ts, int timeout, int nags)
{
	for (struct Addrss** current = head;
		*current != NULL;
		current = &((*current)->next))
	{
top_of_loop:
		if (((*current)->tried >= nags)
			&& (usec_diff(ts, &(*current)->header.ts) > timeout))
		{
			// remove the struct from the list
			if (verbosity > 2)
			{
				printf("discarded: ");
				print_mac((*current)->mac);
			}
			struct Addrss* discard = *current;
			*current = (*current)->next;
			free(discard);

			if (*current != NULL)
			{
				goto top_of_loop;
			}
			else break;
		}
	}
	return 0;
}

int addrss_list_nag
(struct Addrss** head, struct timeval* ts, int timeout, struct Host* host)
{
	for (struct Addrss** current = head;
		*current != NULL;
		current = &((*current)->next))
	{
		if (usec_diff(ts, &(*current)->header.ts) > timeout)
		{
			nag(*current, host);
			// reset timeval to allow for response time
			(*current)->header.ts = *ts;
			(*current)->tried++;
		}
	}
	return 0;
}

// send something to the target MAC to see if it's online
int nag(struct Addrss* addrss, struct Host* host)
{
	uint8_t zeros[16], mapped[12];
	memset(zeros, 0, 16);

	memset(mapped, 0, 10);
	memset(mapped+10, 1, 2);

	// assumes non-subnet addresses have been zero'd (subnet check)
	if (memcmp(addrss->ip, zeros, 16))
	{
		if (!memcmp(addrss->ip, mapped, 12))
		{
			// send an ARP packet?
			if (verbosity > 2)
				printf("try %d, need a way to nag with IPv4\n"
				, (addrss->tried) + 1);
		}
		else
		{
			// send an NDP packet?
			if (verbosity > 2)
				printf("try %d, need a way to nag with IPv6\n"
				, (addrss->tried) + 1);
		}
	}
	return 0;
}

int print_mac(uint8_t* mac)
{
	for(int byte = 0; byte <= 4; byte++)
	{
		printf("%02x:", mac[byte]);
		if (byte >= 4)
		{
			printf("%02x", mac[byte+1]);
		}
	}
	printf("\n");
	return 0;
}

int print_ip(uint8_t* ip)
{
	// TODO, handle IPv4 separately?
	// just print the IPv6 with mapped IPv4 address
	for (int byte = 0; byte <= 12; byte += 2)
	{
		uint16_t group = ((uint16_t)(ip[byte]) << 8)
				| (uint16_t)(ip[byte+1]);
		if (group)
		{
			// shitty approximation of mapped IPv4 output
			if (group == 0x101) printf("::");
			else printf("%x:", group);
		}
		if (byte >= 12)
		{
			uint16_t group =
				((uint16_t)(ip[byte+2]) << 8)
				| (uint16_t)(ip[byte+3]);
			if (group)
			printf("%x\n", group);
		}
	}
	return 0;
}

// check if an IPv6 or mapped IPv4 address is in the provided subnet(s)
// TODO, accept multiple subnets
int subnet_check(uint8_t* ip, struct Subnet* subnet)
{
	uint8_t zeros[16], mapped[12];
	memset(zeros, 0, 16);

	memset(mapped, 0, 10);
	memset(mapped+10, 1, 2);

	// zero out all non-subnet IPs that aren't already zero
	if (memcmp(ip, zeros, 16))
	{
		// check for mapped IPv4 and IPv4 mask
		if (!memcmp(ip, mapped, 12))
		{
			// note, correctly getting non-zero IPv4 addresses

			// mask bytes
			int mb = (subnet->mask - 96) / 8;
			// remnant bits mask
			int mr = (subnet->mask - 96) % 8;
			uint8_t remn =
				(-1) << (8 - mr);

			//note, correct mask

			// last byte
			uint8_t lb = ip[12 + mb];

			//printf("IPv4, mb: %d, lb: %d\n", mb, lb);

			// check full bytes and remnant bits
			if (memcmp(ip + 12, subnet->ip + 12, mb)
				&& lb < remn)
			{
				if (verbosity > 3)
				printf("Zero'd a non-subnet IPv4 address\n");

				memset(ip, 0, 16);
			}
		}
		else
		{
			// note, correctly getting non-zero IPv6 addresses

			// mask bytes
			int mb = subnet->mask / 8;
			// mask remnants
			int mr = subnet->mask % 8;
			// remnant mask
			uint8_t remn = (-1) << mr;

			//note, correct mask

			uint8_t lb = ip[mb];

			//printf("IPv6, mb: %d, lb: %x\n", mb, lb);

			if(memcmp(ip, subnet->ip, mb)
				&& lb < remn)
			{
				if (verbosity > 3)
				printf("Zero'd a non-subnet IPv6 address\n");

				memset(ip, 0, 16);
			}
		}
	}
	return 0;
}

// parse a CIDR notation string and save to a Subnet struct
int parse_cidr(char* cidr, struct Subnet* dest)
{
	char* mask_ptr, *end;
	int retval;

	// parse provided mask
	if ((mask_ptr = strchr(cidr, '/')) != NULL)
	{
		*mask_ptr++ = 0;
		dest->mask = strtol(mask_ptr, &end, 10);

		if ((mask_ptr == end) || *end)
		{
			retval = 0;
			goto end;
		}
	}
	else
	{
		dest->mask = 128;
	}

	// parse provided IP address
	if (inet_pton(AF_INET6, cidr, dest->ip))
	{
		retval = 1;
		goto end;
	}
	else if (inet_pton(AF_INET, cidr, dest->ip+12))
	{
		memset(dest->ip, 0, 10);
		memset(dest->ip+10, 1, 2);
		dest->mask += 96;
		retval = 1;
		goto end;
	}
	else
	{
		retval = 0;
		goto end;
	}

end:
	if (mask_ptr != NULL)
	{
		*--mask_ptr = '/';
	}

	// TODO, do this implicitly above?
	dest->mask > 128 ? (dest->mask = 128) : 0;
	return retval;
}

// fill in the destination with device's MAC address
int get_mac(uint8_t* dest, char* dev)
{
	int fd, rc;
	struct ifreq ifr;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

	// get the MAC address of the interface
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	rc = ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);

	if (!rc)
	{
		if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		{
			warn("Failed to get host MAC address, not ethernet");
			return -1;
		}

		memcpy(dest, (uint8_t*)ifr.ifr_hwaddr.sa_data, 6);

		return 0;
	}
	else
	{
		warn("Failed to get host MAC address");
		return -1;
	}
}

// fill in the destination with device's IPv4 address
int get_ipv4(uint8_t* dest, char* dev)
{
	int fd, rc;
	struct ifreq ifr;

	// fill in the struct
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

	// get the address of the interface
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	rc = ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	if(!rc)
	{	// save the IP address
		memcpy(dest, &((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr,
		sizeof(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));

		// TEMPORARY
		if (verbosity)
		{
			printf("Host IPv4 address:\t%s\n",
			inet_ntoa
			(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
		}

		return 0;
	}
	else
	{
		warn("Failed to get host IP address");
		return -1;
	}
}

// fill in the destination with device's IPv6 address
int get_ipv6(uint8_t* dest, char* dev)
{
	// TODO
	return 0;
}
