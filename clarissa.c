#include "clarissa.h"

// Save the source addresses and receive time from a packet in a struct.
struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header)
{
	struct Addrss addrss = {0};
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
				if (verbosity)
				warn("failed to extract ethernet frame");
				goto fail;
			}

		case DLT_LINUX_SLL:

			warn("\"any\" device not yet supported\n");
			goto fail;

		case DLT_IEEE802_11:

			warn("WLAN is not yet supported\n");
			goto fail;

		default:
			warn("unsupported link type: %i\n",
				pcap_datalink(handle));
			goto fail;
	}

fail:
		return (struct Addrss){0};
}

// get a VLAN tag from the frame and continue handling the frame
int get_tag(const uint8_t* frame, struct Addrss* addrss)
{
	uint16_t type = ((uint16_t)(frame[0]) << 8) | (uint16_t)(frame[1]);
	switch (type)
	{
		case DOT1Q:
		case DOT1AD:
		case DOT1QINQ:

			if ((addrss->tags >> 60) >= 5)
			{
				warn("Exceeded VLAN tag depth!");
				return -1;
			}

			// get the full TCI
			uint64_t VID =
				(((uint64_t)frame[2] << 8)
				+ (uint64_t)frame[3]);

			// drop the PPC and DEI
			VID &= (uint64_t)(1 << 12) - 1;

			// pack the VLAN ID and increment the count
			/* | count |     5x VLAN IDentifiers     |
			   |  4b   | 12b | 12b | 12b | 12b | 12b | */
			addrss->tags += (VID << (addrss->tags >> 60) * 12)
					+ ((uint64_t) 1 << 60);

			addrss->header.caplen -= 4;

			return get_tag(frame + 4, addrss);

		default:
			addrss->header.caplen -= 2;
			return get_eth_ip(frame + 2, addrss,
				type <= 1500 ? ETH_SIZE : type);
	}
}

int get_eth_ip(const uint8_t* frame, struct Addrss* addrss, uint16_t type)
{
	switch (type)
	{
		case IPv4:
			// map IPv4 onto IPv6 address
			memset(addrss->ip, 0, 10);
			memset(addrss->ip+10, 0xFF, 2);
			memcpy(addrss->ip+12, frame+12, 4);
			return 0;

		case ARP:
			// map IPv4 onto IPv6 address
			memset(addrss->ip, 0, 10);
			memset(addrss->ip+10, 0xFF, 2);
			memcpy(addrss->ip+12, frame+14, 4);
			return 0;

		case IPv6:
			// copy IPv6 address to addrss
			memcpy(addrss->ip, frame+8, 16);
			return 0;

		case ETH_SIZE:
			// TODO, determine payload type
			// and extract IP

			// continue without IP
			if (verbosity)
			warn("ETH_SIZE frame found");
			return -1;

		case ARUBA_AP_BC:

			if (verbosity)
			warn("Aruba Instant AP broadcast packet found");
			return -1;

		case EAPOL:

			if (verbosity)
			warn("EAP over LAN packet found");
			return -1;

		case DOT11R:

			if (verbosity)
			warn("Fast BSS Transition (802.11r) packet found");
			return -1;

		default:
			if (verbosity)
			{
				warn("unsupported EtherType: 0x%04x", type);
				printf("From: ");
				print_mac(addrss->mac);
			}

			return -1;
	}
}

// update the list with a new entry
void addrss_list_add(struct Addrss** head, const struct Addrss* new_addrss)
{
	if (is_zeros(new_addrss->mac, 6)) return;

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
			found = 1;

			// update time and ip
			(*current)->header.ts = new_addrss->header.ts;
			(*current)->tried = 0;
			if (!is_zeros(new_addrss->ip, 16))
				memcpy((*current)->ip, new_addrss->ip, 16);

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

		if (verbosity) print_mac(new_addrss->mac);
		if (verbosity > 1) print_ip(new_addrss->ip);
	}
}

// remove timed out elements that exceeded nags
void addrss_list_cull
(struct Addrss** head, const struct timeval* ts,
	const int timeout, const int nags)
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
}

void addrss_list_nag
(struct Addrss** head, const struct timeval* ts,
	const int timeout, const struct Opts* opts)
{
	for (struct Addrss** current = head;
		*current != NULL;
		current = &((*current)->next))
	{
		if (usec_diff(ts, &(*current)->header.ts) > timeout)
		{
			nag(*current, opts);
			// reset timeval to allow for response time
			(*current)->header.ts = *ts;
			(*current)->tried++;
		}
	}
}

// send something to the target MAC to see if it's online
void nag(const struct Addrss* addrss, const struct Opts* opts)
{
	// assumes non-subnet addresses have been zero'd (subnet check)
	if (!is_zeros(addrss->ip, 16))
	{
		// TODO, put the common ethernet stuff here?

		if (is_mapped(addrss->ip))
		{
			// IPv4, send ethernet frame with ARP packet

			// count size of the frame

			// no preamble / SFD
			// MAC addresses
			int count = 12;
			// tag count
			count += (addrss->tags >> 60) * 4;
			//ethertype
			count += 2;
			//arp payload
			count += 28;
			// frame check sequence (CRC32) done by network card?
			uint8_t frame[count];
			int ptr = 0;

			// start of ethernet header

			// fill in destination & source MAC addresses
			memcpy(&frame[ptr], addrss->mac, 6);
			ptr += 6;
			memcpy(&frame[ptr], opts->host.mac, 6);
			ptr += 6;

			// reassemble VLAN tags in the right order
			for (int i = addrss->tags >> 60; i; i--)
			{
				// tag protocol identifier
				// TODO figure out QinQ or drop at capture
				if (i == 1) net_puts(&frame[ptr], DOT1Q);
				else net_puts(&frame[ptr], DOT1AD);
				ptr += 2;

				// Priority Code Point = 1 (background)
				uint16_t tag = 16384;

				// drop eligible
				tag += 8192;

				// unpack VLAN identifier
				tag += (addrss->tags >> (i * 12))
					& (uint64_t)((1 << i) -1);

				// add the tag control info
				net_puts(&frame[ptr], tag);
				ptr += 2;
			}


			// set ARP ethertype
			net_puts(&frame[ptr], ARP);
			ptr += 2;

			// end of ethernet header, start of ARP packet

			// hardware type: ethernet
			net_puts(&frame[ptr], 1);
			ptr += 2;

			// protocol type: IPv4
			net_puts(&frame[ptr], IPv4);
			ptr += 2;

			// hardware address length (one byte, no endianness)
			frame[ptr] = 6;
			ptr += 1;

			// protocol address length (one byte, no endianness)
			frame[ptr] = 4;
			ptr += 1;

			// operation type: request
			net_puts(&frame[ptr], 1);
			ptr += 2;

			// sender hardware address
			memcpy(&frame[ptr], opts->host.mac, 6);
			ptr += 6;

			// sender protocol address (mapped IPv4)
			memcpy(&frame[ptr], opts->host.ipv4+12, 4);
			ptr += 4;

			// target hardware address
			memcpy(&frame[ptr], addrss->mac, 6);
			ptr += 6;

			// target protocol address (mapped IPv4)
			memcpy(&frame[ptr], addrss->ip+12, 4);
			ptr += 4;

			// frame check sequence (CRC) done by network card?

			// send the frame
			if (pcap_inject(opts->handle, &frame, count) != count)
			{
				warn("Failed to inject the frame");
			}
			else if (verbosity > 2)
			{
				printf("ARP packet %d sent to ",
					(addrss->tried) + 1);
				print_ip(addrss->ip);
			}
		}
		else
		{
			// send an NDP packet?
			if (verbosity > 2)
				printf("try %d, need a way to nag with IPv6\n"
				, (addrss->tried) + 1);
		}
	}
}

void print_mac(const uint8_t* mac)
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
}

void print_ip(const uint8_t* ip)
{
	if (!is_zeros(ip, 16))
	{
		if (is_mapped(ip))
		{
			printf("%d.%d.%d.%d",
				ip[12], ip[13], ip[14], ip[15]);
		}
		else
		{
			for (int i = 0; i < 16; i++)
			{
				if (!ip[i])
				{
					if (!ip[i+1]) continue;
					else printf(":");
				}
				if (i && !(i % 2)) printf(":");
				if (ip[i]) printf("%x", ip[i]);
			}
		}

		printf("\n");
	}
}

// check if an IPv6 or mapped IPv4 address is in the provided subnet
// TODO, accept multiple subnets (or use multiple instances)
void subnet_check(uint8_t* ip, struct Subnet* subnet)
{
	if(!is_zeros(ip, 16))
	{
		if (bitcmp(ip, subnet->ip, subnet->mask))
		{
			if (verbosity > 3)
			{
				printf("zerod ip: ");
				print_ip(ip);
			}

			memset(ip, 0, 16);
		}
	}
}

// bitwise compare a to b to n bits
int bitcmp(uint8_t* a, uint8_t* b, int n)
{
	n = n >= 0 ? n : 0;
	int bytes = n / 8;
	int remn = n % 8;
	int cmp = bytes > 0 ? memcmp(a, b, bytes) : 0;

	if (cmp || !remn) return cmp;

	uint8_t mask = ((1 << n) -1) << (8 - remn);

	return (a[bytes] & mask) - (b[bytes] & mask);
}

// parse a CIDR notation string and save to a Subnet struct
int parse_cidr(const char* cidr, struct Subnet* dest)
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
		memset(dest->ip+10, 0xFF, 2);
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
void get_if_mac(uint8_t* dest, const char* dev)
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
			return;
		}

		// copy the MAC address over
		memcpy(dest, (uint8_t*)ifr.ifr_hwaddr.sa_data, 6);
	}
	else
	{
		warn("Failed to get host MAC address");
	}
}

// fill in the destination with device's IP Address of Family [4|6]
void get_if_ip(uint8_t* dest, const char* dev, int AF, char* errbuf)
{
	pcap_if_t* devs;

	// TODO, save all IPv6 addresses for a device
	// and nag with the one with the same prefix
	// can't use uint16_t because of endianness
	uint8_t v6_mask[2] = { 0xfe, 0x80 };

	if (pcap_findalldevs(&devs, errbuf))
	{
		warn("%s\n", errbuf);
		return;
	}

	for (pcap_if_t* d = devs; d != NULL; d = d->next)
	{
		if(!strcmp(d->name, dev))
		{
			for(pcap_addr_t* a = d->addresses;
				a != NULL; a = a->next)
			{
				// TODO, make the logic neater?
				if(a->addr->sa_family == AF_INET
					&& AF == AF_INET)
				{
					// map the IPv4 address
					memset(dest, 0, 10);
					memset(dest+10, 0xFF, 2);
					memcpy(dest+12,
					&((struct sockaddr_in*)
					a->addr)->sin_addr.s_addr, 4);

					// stop at 1 address
					goto end;
				}

				if(a->addr->sa_family == AF_INET6
					&& AF == AF_INET6
					&& !bitcmp((uint8_t*)
						&((struct sockaddr_in6*)
						a->addr)->sin6_addr.s6_addr,
						v6_mask, 16)
					)
				{
					memcpy(dest, &((struct sockaddr_in6*)
					a->addr)->sin6_addr.s6_addr, 16);

					// stop at 1 address
					goto end;
				}
			}
			// stop at the device we're looking for
			goto end;
		}
	}

end:
	pcap_freealldevs(devs);

}

// put the source's upper and lower 8 bits in in net endianness into target
inline void net_puts(uint8_t* target, uint16_t source)
{
	target[0] = (source >> 8) & 0xFF;
	target[1] = (source) & 0xFF;
}

// check if a run of count bytes at target are all zero
int is_zeros(const uint8_t* target, int count)
{
	while (count--)
	{
		if (target[count]) return 0;
	}
	return 1;
}

// check if a given IP address is an IPv4-mapped IPv6 address
int is_mapped(const uint8_t* ip)
{
	return ((uint64_t*) ip)[0] == 0
		&& ((uint16_t*) ip)[4] == 0
		&& ((uint16_t*) ip)[5] == 0xFFFF;
}

// write The list out to a file
void dump_state(char* filename, struct Addrss *head) {
	char* tmp_filename;
	asprintf(&tmp_filename, "%s.XXXXXX", filename);
	int tmp_fd = mkstemp(tmp_filename);
	if (tmp_fd < 0) {
		warn("Failed to create temp file");
		return;
	}
	FILE* stats_file = fdopen(tmp_fd, "w");
	if (stats_file == NULL) {
		warn("Failed to open stats file");
		return;
	}
	flockfile(stats_file);
	for (struct Addrss *link = head; link != NULL; link = link->next) {
		for (int i = 0; i < 6; i++) {
			fprintf(stats_file, "%02x%c",
				link->mac[i], (i==5)?'\n':':');
		}
	}
	funlockfile(stats_file);
	fclose(stats_file);

	if ((rename(tmp_filename, filename) < 0) || chmod(filename, 0444)) {
		warn("Failed to rename stats file");
	}
}

void get_if_ipv4_subnet(struct Subnet* subnet, struct Opts* opts)
{
	// get IPv4 subnet base address and actual mask
	uint32_t netp, maskp;
	pcap_lookupnet(opts->dev, &netp, &maskp, opts->errbuf);

	// save base address mapped to IPv6
	memset(subnet->ip, 0, 16);
	memset(subnet->ip+10, 0xFF, 2);
	memcpy(&subnet->ip[12], &netp, 4);

	// save the number of set bits in the mask
	subnet->mask = 0;
	while (maskp)
	{
		subnet->mask += maskp & 1;
		maskp >>= 1;
	}
	// adjust for mapping
	subnet->mask += 96;
}
