#include "clarissa.h"
#include "clarissa_internal.h"

// Save the source addresses and receive time from a packet in a struct.
struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header)
{
	struct Addrss addrss = {0};
	addrss.header = *header;

	// assume a packet is correct (discard len < caplen (74) ?)
	// an invalid MAC will be unreachable and get purged
	// check if the IP is in the right range later?

	// link type is separately stored metadata
	switch (pcap_datalink(handle))
	{
		case DLT_EN10MB:

			// preamble and start of frame delimiter not included

			// skip to source MAC address and store it
			memcpy(addrss.mac, frame += 6, 6);

			// skip to metadata and get IP address
			if (get_tag(frame += 6, &addrss)) return addrss;
			else if (verbosity > 3)
				warn("failed to extract ethernet frame");

			goto fail;

		case DLT_LINUX_SLL:
	// as per https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
		{
			int bail = 0;
			switch (net_get_u16(frame += 2))
			{
				// unsupported ARPHRD_ types
				case 824: // ARPHRD_NETLINK
				case ARPHRD_IPGRE:
				case ARPHRD_IEEE80211_RADIOTAP:
					// if DLT_IEEE802_11 gets support,
					// go there?
					if (verbosity > 4)
						warn
					("unknown ARPHRD_ type found");

					bail = 1;
			}

			// only get the 6 byte link-layer addresses
			uint8_t len[2] = {0};
			uint16_t mac_len = 6;
			net_put_u16(len, mac_len);
			if (memcmp(len, frame += 2, 2))
			{
				if (verbosity > 3)
					warn
		("unsupported link-layer address length on \"any\" device");
				goto fail;
			}
			memcpy(addrss.mac, frame += 2, 6);

			if (bail) return addrss;

			// can't nag on "any" device, dead code...
			return addrss;
			/*
			// SLL reserves 8 bytes for link-layer address
			frame += 8;

			uint16_t type = net_get_u16(frame);
			switch (type)
			{
				// non ethertype values of SLL protocol type
				case 0x0001:
				case 0x0002:
				case 0x0003:
				case 0x0004:
				case 0x000C: return addrss;
			}
			if (get_eth_ip(frame += 2, &addrss,
				type <= 1500 ? ETH_SIZE : type))
			{
				return addrss;
			}
			else if (verbosity > 3)
				warn
				("failed to extract \"any\" ethernet frame");
			goto fail;
			*/
		}

		case DLT_IEEE802_11:

			warn("WLAN is not yet supported");
			goto fail;

		default:
			warn("unsupported link type: %i",
				pcap_datalink(handle));
			goto fail;
	}

fail:
		return (struct Addrss){0};
}

// get a VLAN tag from the frame and continue handling the frame
int get_tag(const uint8_t* frame, struct Addrss* addrss)
{
	uint16_t type = net_get_u16(frame);
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
			return 1;

		case ARP:
			// map IPv4 onto IPv6 address
			memset(addrss->ip, 0, 10);
			memset(addrss->ip+10, 0xFF, 2);
			memcpy(addrss->ip+12, frame+14, 4);
			return 1;

		case IPv6:
			// copy IPv6 address to addrss
			memcpy(addrss->ip, frame+8, 16);
			return 1;

		case ETH_SIZE:
			// TODO, determine payload type
			// and extract IP

			// continue without IP
			if (verbosity > 3)
			warn("ETH_SIZE frame found");
			return 0;

		case ARUBA_AP_BC:

			if (verbosity)
			warn("Aruba Instant AP broadcast packet found");
			return 0;

		case EAPOL:

			if (verbosity)
			warn("EAP over LAN packet found");
			return 0;

		case DOT11R:

			if (verbosity)
			warn("Fast BSS Transition (802.11r) packet found");
			return 0;

		default:
			if (verbosity)
			{
				warn("unsupported EtherType: 0x%04X", type);
				printf("From: ");
				print_mac(addrss->mac);
			}

			return 0;
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
		if (verbosity > 2) print_ip(new_addrss->ip);
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
			if (verbosity > 1)
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
	const int timeout, const struct Opts* opts, uint64_t* count)
{
	for (struct Addrss** current = head;
		*current != NULL;
		current = &((*current)->next))
	{
		if (usec_diff(ts, &(*current)->header.ts) > timeout)
		{
			nag(*current, opts, count);
			(*current)->tried++;
		}
	}
}

// send something to the target MAC to see if it's online
void nag(const struct Addrss* addrss,
	 const struct Opts* opts, uint64_t* count)
{
	// assumes non-subnet addresses have been zero'd (subnet check)
	if (!is_zeros(addrss->ip, 16))
	{
		*count += 1;
		if (is_mapped(addrss->ip))
		{
			send_arp(addrss, opts);
		}
		else
		{
			send_ndp(addrss, opts);
		}
	}
}

// print the string representation of a MAC address to stdout
void print_mac(const uint8_t* mac)
{
	char* tmp;
	asprint_mac(&tmp, mac);
	printf("%s\n", tmp);
	free(tmp);
}

// same but to a string (remember to free *dest!)
void asprint_mac(char** dest, const uint8_t* mac)
{
	if (-1 == asprintf(dest, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]))
	err(2, "Error printing");
}

// print the string representation of an IPv[4|6] to stdout
void print_ip(const uint8_t* ip)
{
	char* tmp;
	asprint_ip(&tmp, ip);
	printf("%s", tmp);
	if (strncmp(tmp, "", 1)) printf("\n");
	free(tmp);
}

// same but to a string (remember to free *dest!)
void asprint_ip(char** dest, const uint8_t* ip)
{
	if (is_zeros(ip, 16))
	{
		*dest = malloc(1);
		**dest = 0;
	}
	else
	{
		if (is_mapped(ip))
		{
			if (asprintf(dest, "%d.%d.%d.%d",
				ip[12], ip[13], ip[14], ip[15]) == -1)
			{
				err(1, "Failed to asprintf an IPv4 address");
			}
		}
		else
		{
			// this is surprisingly complicated...
			*dest = malloc(INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, ip,
				*dest, INET6_ADDRSTRLEN);
		}
	}
}

// zero IPv4 non-subnet addresses and IPv6 multicast addresses
void subnet_filter(uint8_t* ip, struct Subnet* subnet)
{
	if (!is_zeros(ip, 16))
	{
		uint8_t multicast = 0xFF;
		if (	!memcmp(ip, &multicast, 1)
			|| (is_mapped(ip)
			&& bitcmp(ip, subnet->ip, subnet->mask)))
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
int get_cidr(struct Subnet* dest, const char* cidr)
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

	if (!dev || !strncpy(ifr.ifr_name, dev, IFNAMSIZ-1))
	{
		warn("No device to get MAC address for");
		return;
	}

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
		warn("Failed to get host MAC address, may be due to \"any\" device");
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

	if (!dev || pcap_findalldevs(&devs, errbuf))
	{
		return;
	}

	for (pcap_if_t* d = devs; d != NULL; d = d->next)
	{
		if (strcmp(d->name, dev)) continue;

		for(pcap_addr_t* a = d->addresses;
			a != NULL; a = a->next)
		{
			// TODO, make the logic neater?
			if (a->addr->sa_family == AF_INET
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

			if (a->addr->sa_family == AF_INET6
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

end:
	pcap_freealldevs(devs);

}

// put the source's uint16 into target in network byte order
inline void net_put_u16(uint8_t* target, const uint16_t source)
{
	target[0] = (source >> 8) & 0xFF;
	target[1] = (source) & 0xFF;
}

// copy from host to network byte order
inline void net_put_u32(uint8_t* target, const uint32_t source)
{
	target[0] = (source >> 24) & 0xFF;
	target[1] = (source >> 16) & 0xFF;
	target[2] = (source >> 8) & 0xFF;
	target[3] = (source) & 0xFF;
}

inline uint16_t net_get_u16(const uint8_t* source)
{
	return 	( (uint16_t)(source[0] << 8)
		| (uint16_t)(source[1])
		);
}

inline uint32_t net_get_u32(const uint8_t* source)
{
	return 	( (uint32_t)(source[0] << 24)
		| (uint32_t)(source[1] << 16)
		| (uint32_t)(source[2] << 8)
		| (uint32_t)(source[3])
		);
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
	if (asprintf(&tmp_filename, "%s.XXXXXX", filename) == -1)
	{
		errx(1, "Failed to save temporary filename");
	}
	int tmp_fd = mkstemp(tmp_filename);
	if (tmp_fd < 0) {
		warn("Failed to create temp file");
		goto end;
	}
	FILE* stats_file = fdopen(tmp_fd, "w");
	if (stats_file == NULL) {
		warn("Failed to open stats file");
		goto end;
	}
	flockfile(stats_file);
	char* tmp_mac;
	char* tmp_ip;
	for (struct Addrss *link = head; link != NULL; link = link->next) {
		asprint_mac(&tmp_mac, link->mac);
		asprint_ip(&tmp_ip, link->ip);
		fprintf(stats_file, "%s\t%s\n", tmp_mac, tmp_ip);
		free(tmp_mac);
		free(tmp_ip);
	}
	funlockfile(stats_file);
	fclose(stats_file);

	if ((rename(tmp_filename, filename) < 0) || chmod(filename, 0444)) {
		warn("Failed to rename stats file");
	}
end:
	free(tmp_filename);
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

// IPv4, send ethernet frame with ARP packet
void send_arp(const struct Addrss* addrss, const struct Opts* opts)
{
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

	fill_eth_hdr(frame, &ptr, addrss, opts);

	// set the ethertype
	net_put_u16(&frame[ptr], ARP);
	ptr += 2;

	// end of ethernet header, start of ARP packet

	// hardware type: ethernet
	net_put_u16(&frame[ptr], 1);
	ptr += 2;

	// protocol type: IPv4
	net_put_u16(&frame[ptr], IPv4);
	ptr += 2;

	// hardware address length (one byte, no endianness)
	frame[ptr] = 6;
	ptr += 1;

	// protocol address length (one byte, no endianness)
	frame[ptr] = 4;
	ptr += 1;

	// operation type: request
	net_put_u16(&frame[ptr], 1);
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

	// frame check sequence (CRC) done by NIC?

	// send the frame
	if (pcap_inject(opts->handle, &frame, count) != count)
	{
		warn("Failed to inject ARP frame");
	}
	else if (verbosity > 2)
	{
		printf("ARP packet %d sent to ",
			(addrss->tried) + 1);
		print_ip(addrss->ip);
	}
}

// send an ICMPv6 NDP Neighbor Solicitation packet
void send_ndp(const struct Addrss* addrss, const struct Opts* opts)
{
	// count size of the frame

	// includes 6 byte MAC address option, and 2 bytes: type and link
	uint16_t NDP_NS_size = 32;

	// no preamble / SFD
	// MAC addresses
	uint8_t count = 12;
	// tag count
	count += (addrss->tags >> 60) * 4;
	//ethertype
	count += 2;
	// IPv6 header
	count += 40;
	// ICMPv6 neighbor solicitation
	count += NDP_NS_size;

	// end of count

	uint8_t frame[count];
	int ptr = 0;

	// start of ethernet header

	fill_eth_hdr(frame, &ptr, addrss, opts);

	// set the ethertype
	net_put_u16(&frame[ptr], IPv6);
	ptr += 2;

	// end of ethernet header, start of IPv6 packet header

	/* DS field + ECN, previously called traffic class?
	   DSCP 0 == default behaviour, ECN 0 == not using ECN
	| version | DS field | ECN |       flow label           |
	|  0110   |  000000  | 00  | 0000 | 00000000 | 00000000 |
	|-------------------------------------------------------|
	|  0110   0000 | 00    00    0000 | 00000000 | 00000000 |
	|    byte 0    |      byte 1      |  byte 2  |  byte 3  |
	*/

	uint8_t version = 6;
	memset(&frame[ptr], version << 4, 1);
	ptr += 1;
	memset(&frame[ptr], 0, 3);
	ptr += 3;

	// payload length
	net_put_u16(&frame[ptr], NDP_NS_size);
	ptr += 2;

	// next header = ICMPv6
	uint8_t ICMPv6_next = 58;
	memset(&frame[ptr], ICMPv6_next, 1);
	ptr += 1;

	// hop limit, RFC4861 says it should be 255?
	memset(&frame[ptr], 255, 1);
	ptr += 1;

	// source IPv6 address
	memcpy(&frame[ptr], opts->host.ipv6, 16);
	ptr += 16;

	// destination IPv6 address
	memcpy(&frame[ptr], addrss->ip, 16);
	ptr += 16;

	// next header is ICMPv6, no extension headers used

	// end of IPv6 header start of ICMPv6 payload

	// start of ICMPv6 checksum
	int csum_start = ptr;

	// type = neighbor solicitation
	memset(&frame[ptr], 135, 1);
	ptr += 1;

	// code = 0, no sub-function for this type
	memset(&frame[ptr], 0, 1);
	ptr += 1;

	// checksum placeholder
	int csum_ptr = ptr;
	memset(&frame[ptr], 0, 2);
	ptr += 2;

	// pseudo header
		uint8_t pseudo_hdr[40];
		int pseudo_ptr = 0;
		// source IPv6 address
		memcpy(&pseudo_hdr[pseudo_ptr], opts->host.ipv6, 16);
		pseudo_ptr += 16;

		// destination IPv6 address
		memcpy(&pseudo_hdr[pseudo_ptr], addrss->ip, 16);
		pseudo_ptr += 16;

		// "upper-layer packet length", 4 bytes, right endianness?
		net_put_u32(&pseudo_hdr[pseudo_ptr], (uint32_t) NDP_NS_size);
		pseudo_ptr += 4;

		// "zero", as per RFC8200
		memset(&pseudo_hdr[pseudo_ptr], 0, 3);
		pseudo_ptr += 3;

		memcpy(&pseudo_hdr[pseudo_ptr], &ICMPv6_next, 1);
		pseudo_ptr += 1;

		uint16_t pseudo_csum = inet_csum_16(pseudo_hdr, 40, 0);

	// 4 bytes reserved, must be zeros
	memset(&frame[ptr], 0, 4);
	ptr += 4;

	// target address
	memcpy(&frame[ptr], addrss->ip, 16);
	ptr += 16;

	// source link-layer address option

	// type = source link-layer address
	memset(&frame[ptr], 1, 1);
	ptr += 1;
	// length = 1 (x 8 octets) (includes these 2 option header bytes)
	memset(&frame[ptr], 1, 1);
	ptr += 1;
	memcpy(&frame[ptr], opts->host.mac, 6);
	ptr += 6;

	// overwrite placeholder checksum with the real? deal
	uint16_t csum = inet_csum_16(frame + csum_start,
				ptr - csum_start, ~pseudo_csum);
	memcpy(frame + csum_ptr, (uint8_t*)&csum, 2);

	// frame check sequence (CRC) done by NIC?

	// send the frame
	if (pcap_inject(opts->handle, &frame, count) != count)
	{
		warn("Failed to inject NDP frame");
	}
	else if (verbosity > 2)
	{
		printf("NDP packet %d sent to ",
			(addrss->tried) + 1);
		print_ip(addrss->ip);
	}
}

// TODO, confirm this handles endianness correctly and portably
// fill in an ethernet header minus the ethertype
void fill_eth_hdr
(uint8_t* frame, int* ptr,
	const struct Addrss* addrss, const struct Opts* opts)
{
        // fill in destination & source MAC addresses
        memcpy(&frame[*ptr], addrss->mac, 6);
        *ptr += 6;
        memcpy(&frame[*ptr], opts->host.mac, 6);
        *ptr += 6;

        // reassemble VLAN tags in the right order
        for (int i = addrss->tags >> 60; i; i--)
        {
                // tag protocol identifier
                // TODO figure out QinQ or drop at capture
                if (i == 1) net_put_u16(&frame[*ptr], DOT1Q);
                else net_put_u16(&frame[*ptr], DOT1AD);
                *ptr += 2;

                // Priority Code Point = 1 (background)
                uint16_t tag = 16384;

                // drop eligible
                tag += 8192;

                // unpack VLAN identifier
                tag += (addrss->tags >> (i * 12))
                        & (uint64_t)((1 << i) -1);

                // add the tag control info
                net_put_u16(&frame[*ptr], tag);
                *ptr += 2;
        }
}

// 16 bit one's compliment checksum, per RFC1071
uint16_t inet_csum_16(uint8_t* addr, int count, uint16_t start)
{
	register int32_t sum = start;

	while (count > 1)
	{
		// inner loop
		sum += *(uint16_t*)addr;
		addr += 2;
		count -= 2;
	}

	// add last byte if count was uneven
	if (count > 0) sum += *(uint8_t*)addr;

	// fold the 32 bit sum to 16 bits
	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}
