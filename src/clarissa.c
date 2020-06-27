#include "clarissa.h"

#include <stdlib.h>	// free(), strtol()
#include <err.h>	// warn()
#include <string.h>	// mem*(), strn*()
#include <arpa/inet.h>	// inet_pton(), struct sockaddr_in
#include <sys/ioctl.h>	// ioctl(), SIOCGIFADDR
#include <net/if.h>	// struct ifreq, IFNAMSIZ
#include <unistd.h>	// close()
#include <net/if_arp.h>	// ARPHRD_*
#include <stdio.h>	// asprintf()

#include "../get_hardware_address/get_hardware_address.h"

// extraction
int get_tag(const uint8_t* frame, intptr_t max, struct Addrss* addrss);
int get_eth_ip(const uint8_t* frame, intptr_t max, struct Addrss* addrss,
		const uint16_t type);

// helpers
int bitcmp(const uint8_t* a, const uint8_t* b, int n);
void asprint_ipv4(char** dest, const uint8_t* ip);

// network output
void nag(const struct Addrss* addrss,
	 const struct Opts* opts, uint64_t* count);
void send_arp(const struct Addrss* addrss, const struct Opts* opts);
void send_ndp(const struct Addrss* addrss, const struct Opts* opts);
// helpers
void fill_eth_hdr
(uint8_t* frame, int* ptr, const struct Addrss* addrss,
	const struct Opts* opts);
void net_put_u16(uint8_t* target, const uint16_t source);
void net_put_u32(uint8_t* target, const uint32_t source);
uint16_t net_get_u16(const uint8_t* source);
uint32_t net_get_u32(const uint8_t* source);
uint16_t inet_csum_16(uint8_t* addr, int count, uint16_t start);

// Save the source addresses and receive time from a packet in a struct.
struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header)
{
	if (header->len < header->caplen)
	{
		warnx("Frame is shorter than required");
		goto fail;
	}
	struct Addrss addrss = {0};

	intptr_t max = (intptr_t)frame + header->caplen;

	addrss.ts = header->ts;

	// assume a packet is correct
	// an invalid MAC will be unreachable and get purged
	// IP may go through subnet_filter() later
	// and an empty result should get caught by addrss_valid()

	// if an IP is extracted, addrss.ip is set to true
	// if that IP is v6, addrss.v6 is set to true
	// the capture time for this is saved
	// at the label "end"

	// link type is separately stored metadata
	switch (pcap_datalink(handle))
	{
		case DLT_EN10MB:

			// preamble and start of frame delimiter not included

			// skip to source MAC address and store it
			// check bounds and fail on zeros MAC
			if ((intptr_t)frame + (6 + 6) > max
				|| is_zeros(frame + 6, 6))
			{
				warnx("Exceeded capture length or MAC is zeros");
				goto fail;
			}
			memcpy(addrss.mac, frame += 6, 6);

			// skip to metadata and get IP address
			if (get_tag(frame += 6, max, &addrss)) goto end;
			else
			{
				if (verbosity > 3)
				warnx("Failed to extract ethernet frame");

				goto fail;
			}

		case DLT_LINUX_SLL:
	// as per https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
		{
			bool bail = false;
			if ((intptr_t)frame + 2 > max)
			{
				warnx("Exceeded frame length at DLT_LINUX_SLL, 0");
				goto fail;
			}
			switch (net_get_u16(frame += 2))
			{
				// unsupported ARPHRD_ types
				case 824:	// ARPHRD_NETLINK
				case 778: 	// ARPHRD_IPGRE
				case 803:	// ARPHRD_IEEE80211_RADIOTAP
					// if DLT_IEEE802_11 gets support,
					// go there?
					if (verbosity > 4)
						warnx
					("Unknown ARPHRD_ type found");

					bail = true;
			}

			// only get the 6 byte link-layer addresses
			uint8_t len[2] = {0};
			uint16_t mac_len = 6;
			net_put_u16(len, mac_len);
			if ((intptr_t)frame + 2 > max)
			{
				warnx("Exceeded frame length at DLT_LINUX_SLL, 1");
				goto fail;
			}
			if (memcmp(len, frame += 2, 2))
			{
				if (verbosity > 3)
					warnx
		("Unsupported link-layer address length on \"any\" device");
				goto fail;
			}
			if ((intptr_t)frame + (2 + 6) > max)
			{
				warnx("Exceeded frame length at DLT_LINUX_SLL, 2");
				goto fail;
			}
			memcpy(addrss.mac, frame += 2, 6);

			if (bail == true) goto end;

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
				case 0x000C: goto end;
			}
			if (get_eth_ip(frame += 2, max, &addrss,
				type <= 1500 ? ETH_SIZE : type))
			{
				goto end;
			}
			else
			{
				if (verbosity > 3)
					warnx
				("Failed to extract \"any\" ethernet frame");

				goto fail;
			}
		}

		case DLT_IEEE802_11:

			warnx("WLAN is not yet supported");
			goto fail;

		default:
			warnx("Unsupported link type: %i",
				pcap_datalink(handle));
			goto fail;
	}

fail:
	if (verbosity > 4)
	{
		warnx("Failed to extract a frame");
	}
	return (struct Addrss){0};
end:
	if (addrss.ip)
	{
		if (addrss.v6 == true)
		{
			addrss.ipv6_t = addrss.ts;
		}
		else
		{
			addrss.ipv4_t = addrss.ts;
		}
	}
	return addrss;
}

// get a VLAN tag from the frame and continue handling the frame
int get_tag(const uint8_t* frame, intptr_t max, struct Addrss* addrss)
{
	if ((intptr_t)frame > max) return -1;
	uint16_t type = net_get_u16(frame);
	switch (type)
	{
		case DOT1Q:
		case DOT1AD:
		case DOT1QINQ:

			if ((intptr_t)frame + 3 > max) return -1;

			if ((addrss->tags >> 60) >= 5)
			{
				warnx("Exceeded VLAN tag depth!");
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

			return get_tag(frame + 4, max, addrss);

		default:
			return get_eth_ip(frame + 2, max, addrss,
				type <= 1500 ? ETH_SIZE : type);
	}
}

int get_eth_ip(const uint8_t* frame, intptr_t max, struct Addrss* addrss, uint16_t type)
{
	switch (type)
	{
		case IPv4:
			if ((intptr_t)frame + (12 + 4) > max) return -1;
			memcpy(addrss->ipv4, frame + 12, 4);
			addrss->ip = true;
			return 1;

		case ARP:
			if ((intptr_t)frame + (14 + 4) > max) return -1;
			memcpy(addrss->ipv4, frame + 14, 4);
			addrss->ip = true;
			return 1;

		case IPv6:
			if ((intptr_t)frame + (8 + 16) > max) return -1;
			// copy IPv6 address to addrss
			memcpy(addrss->ipv6, frame + 8, 16);
			addrss->ip = true;
			addrss->v6 = true;
			return 1;

		case ETH_SIZE:
			// TODO, determine payload type
			// and extract IP

			// continue without IP
			if (verbosity > 3)
			warnx("ETH_SIZE frame found");
			return 0;

		case ARUBA_AP_BC:

			if (verbosity)
			warnx("Aruba Instant AP broadcast packet found");
			return 0;

		case EAPOL:

			if (verbosity)
			warnx("EAP over LAN packet found");
			return 0;

		case DOT11R:

			if (verbosity)
			warnx("Fast BSS Transition (802.11r) packet found");
			return 0;

		default:
			if (verbosity)
			{
				warnx("unsupported EtherType: 0x%04X", type);
				printf("From: ");
				print_mac(addrss->mac);
			}

			return 0;
	}
}

// update the list with a new entry
void addrss_list_add(struct Addrss** head
		, const struct Addrss* new_addrss)
{
	if (is_zeros(new_addrss->mac, 6)) return;

	bool found = false;

	// go through the list while keeping a pointer
	// to the previous pointer
	for (struct Addrss** current = head;
		*current != NULL;
		current = &((*current)->next))
	{
		// check if this has the new MAC address
		if (!memcmp((*current)->mac, new_addrss->mac, 6))
		{
			found = true;

			(*current)->tried = 0;

			(*current)->ts = new_addrss->ts;
			(*current)->ip = new_addrss->ip;
			(*current)->v6 = new_addrss->v6;

			// if an IP was found
			if ((*current)->ip == true)
			{
				// update IP and time for latest pair
				if ((*current)->v6 == true)
				{
					// copy the IP
					if (!is_zeros(new_addrss->ipv6
						, sizeof(new_addrss->ipv6)))
					{
						memcpy((*current)->ipv6
							, new_addrss->ipv6
						, sizeof((*current)->ipv6));
					}

					// copy the timestamp
					// not in the !is_zeros() block
					// in case an actual all zeros IP was seen
					(*current)->ipv6_t =
						new_addrss->ipv6_t;
				}
				else
				{
					if (!is_zeros(new_addrss->ipv4
						, sizeof(new_addrss->ipv4)))
					{
						memcpy((*current)->ipv4
							, new_addrss->ipv4
						, sizeof((*current)->ipv4));
					}

					(*current)->ipv4_t =
						new_addrss->ipv4_t;
				}
			}

			// move it to the start of the list
			if (current != head) {
				struct Addrss* move = *current;
				*current = (*current)->next;
				move->next = *head;
				*head = move;

				break;
			}
		}
	}

	// prepend new_addrss if it's MAC was not found
	if (found == false)
	{
		struct Addrss *new_head = malloc(sizeof *new_head);
		*new_head = *new_addrss;
		new_head->next = *head;
		*head = new_head;

		if (verbosity) print_mac(new_addrss->mac);
		if (new_addrss->ip && verbosity > 2)
		{
			print_ip( new_addrss->v6
				? new_addrss->ipv6
				: new_addrss->ipv4
				, new_addrss->v6);
		}
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
			&& (usec_diff(ts, &(*current)->ts) > timeout))
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
		if (usec_diff(ts, &(*current)->ts) > timeout)
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
	// assumes non-subnet addresses have been zero'd (subnet_filter())
	if (!is_zeros(addrss->v6
			? addrss->ipv6
			: addrss->ipv4
			, sizeof( addrss->v6
				? addrss->ipv6
				: addrss->ipv4)))
	{
		// increment count of packets sent
		*count += 1;

		if (addrss->v6 == true)
		{
			send_ndp(addrss, opts);
		}
		else
		{
			send_arp(addrss, opts);
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
void print_ip(const uint8_t* ip, const bool v6)
{
	char* tmp;
	asprint_ip(&tmp, ip, v6);
	printf("%s\n", tmp);
	free(tmp);
}

// same but to a string (remember to free *dest!)
void asprint_ip(char** dest, const uint8_t* ip, const bool v6)
{
	if (v6 == false)
	{
		asprint_ipv4(dest, ip);
	}
	else
	{
		// this is surprisingly complicated...
		*dest = malloc(INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, ip,
			*dest, INET6_ADDRSTRLEN);
	}
}

void asprint_ipv4(char** dest, const uint8_t* ip)
{
		if (asprintf(dest, "%d.%d.%d.%d",
			ip[0], ip[1], ip[2], ip[3]) == -1)
		{
			err(1, "Failed to asprintf an IPv4 address");
		}
}

// zero non-subnet(/prefix) and multicast IP addresses
// NOTE: clarissa can currently not obtain IPv6 prefixes
// so a zero length prefix should be given for IPv6 addresses
void
subnet_filter(uint8_t* ip, const struct Subnet* subnet,const bool v6)
{
	if (!is_zeros(ip, v6 ? 16 : 4))
	{

		// zero IP if it has 0xff (multicast)
		if ( *((uint8_t*)ip + (v6 ? 0 : 12)) == 0xff
			// or if it doesn't match the given subnet
			|| ((!v6 || (v6 && is_mapped(ip)))
			&& bitcmp(ip, subnet->ip + (v6 ? 0 : 12)
				  , subnet->mask - (v6 ? 0 : 96))))
		{
			if (verbosity > 3)
			{
				printf("zerod ip: ");
				print_ip(ip, v6);
			}

			memset(ip, 0, v6 ? 16 : 4);
		}
	}
}

// bitwise compare a to b to n bits
int bitcmp(const uint8_t* a, const uint8_t* b, int n)
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
	// get_hardware_address brings it all down on failure
	if (!strncmp(dev, "any", 3))
	{
		warnx("Can't get MAC address for \"any\" device");
		return;
	}
	// separate project
	// https://gitlab.com/evils/get_hardware_address
	// portable thanks to the arp-scan contributors
	get_hardware_address(dev, dest);
}

// fill in the destination with device's IP Address of Family [4|6]
void get_if_ip(uint8_t* dest, const char* dev, int AF, char* errbuf)
{
	pcap_if_t* devs;

	// TODO, save all IPv6 addresses for a device
	// and nag with the one with the same prefix

	// link local prefix
	// can't use uint16_t because of endianness
	uint8_t v6_mask[2] = { 0xfe, 0x80 };

	if (!dev || pcap_findalldevs(&devs, errbuf)) return;

	for (pcap_if_t* d = devs; d != NULL; d = d->next)
	{
		if (strcmp(d->name, dev)) continue;

		for (pcap_addr_t* a = d->addresses;
			a != NULL; a = a->next)
		{
			// TODO, make the logic neater?
			if (AF == AF_INET
				&& a->addr->sa_family == AF_INET)
			{
				memcpy(dest, &((struct sockaddr_in*)
				a->addr)->sin_addr.s_addr, 4);

				// stop at 1 address
				goto end;
			}

			if (AF == AF_INET6
				&& a->addr->sa_family == AF_INET6
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
bool is_zeros(const uint8_t* target, int count)
{
	while (count--)
	{
		if (target[count]) return false;
	}
	return true;
}

// check if a given IP address is an IPv4-mapped IPv6 address
bool is_mapped(const uint8_t* ip)
{
	return ((uint64_t*) ip)[0] == 0
		&& ((uint16_t*) ip)[4] == 0
		&& ((uint16_t*) ip)[5] == 0xFFFF;
}

// write The list out to a file
void dump_state(char* filename, struct Addrss *head)
{
	char* tmp_filename;

	if (asprintf(&tmp_filename, "%s.XXXXXX", filename) == -1)
	{
		errx(1, "Failed to save temporary filename");
	}

	int tmp_fd = mkstemp(tmp_filename);

	if (tmp_fd < 0)
	{
		warn("Failed to create temp file");
		goto end;
	}

	FILE* stats_file = fdopen(tmp_fd, "w");

	if (stats_file == NULL)
	{
		warn("Failed to open stats file");
		goto end;
	}

	flockfile(stats_file);

	char* header;
	asprint_clar_header(&header);
	fprintf(stats_file, "%s", header);
	free(header);

	for (struct Addrss *link = head;
		link != NULL; link = link->next)
	{
		char* clar;
		if (asprint_clar(&clar, link) != 0)
		{
			warnx("Prematurely stopping file output");
			break;
		}
		fprintf(stats_file, "%s", clar);
		free(clar);
	}

	funlockfile(stats_file);
	fclose(stats_file);

	if ((rename(tmp_filename, filename) < 0)
			|| chmod(filename, 0444))
	{
		warn("Failed to rename stats file");
	}

end:
	free(tmp_filename);
}

void get_if_ipv4_subnet(struct Subnet* subnet, struct Opts* opts)
{
	// get IPv4 subnet base address and actual mask
	uint32_t netp, maskp;
	pcap_lookupnet(opts->s_dev, &netp, &maskp, opts->errbuf);

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

	// sender protocol address
	memcpy(&frame[ptr], opts->host.ipv4, 4);
	ptr += 4;

	// target hardware address
	memcpy(&frame[ptr], addrss->mac, 6);
	ptr += 6;

	// target protocol address
	memcpy(&frame[ptr], addrss->ipv4, 4);
	ptr += 4;

	// frame check sequence (CRC) done by NIC?

	// send the frame
	if (pcap_inject(opts->s_handle, &frame, count) != count)
	{
		warnx("Failed to inject ARP frame");
	}
	else if (verbosity > 2)
	{
		printf("ARP packet %d sent to ",
			(addrss->tried) + 1);
		print_ip(addrss->ipv4, false);
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
	memcpy(&frame[ptr], addrss->ipv6, 16);
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
		memcpy(&pseudo_hdr[pseudo_ptr], addrss->ipv6, 16);
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
	memcpy(&frame[ptr], addrss->ipv6, 16);
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
	if (pcap_inject(opts->s_handle, &frame, count) != count)
	{
		warnx("Failed to inject NDP frame");
	}
	else if (verbosity > 2)
	{
		printf("NDP packet %d sent to ",
			(addrss->tried) + 1);
		print_ip(addrss->ipv6, true);
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

// for debugging
void print_addrss(const struct Addrss* addrss)
{
	print_mac(addrss->mac);
	print_ip(addrss->ipv4, false);
	print_ip(addrss->ipv6, true);
	printf("\n");
}

// quick check for mac and timeval
bool addrss_valid(const struct Addrss* addrss)
{
	return !is_zeros(addrss->mac, 6);
}

// assemble a FORMAT_VERSION output string
int asprint_clar(char** dest, const struct Addrss* addrss)
{
	char* mac;
	char* ipv4;
	char* ipv6;
	if (is_zeros(addrss->mac, sizeof(addrss->mac)))
	{
		if (verbosity)
		{
			warnx("Refusing to print a all zeros MAC address");
		}
		return 1;
	}
	asprint_mac(&mac, addrss->mac);
	asprint_ip(&ipv4, addrss->ipv4, false);
	asprint_ip(&ipv6, addrss->ipv6, true);

	// v1.x output format
	if (asprintf(dest, "%-17s   %-10li   %-15s   %-10li   %-39s   %0li\n"
				, mac
				, (long int)addrss->ts.tv_sec
				, ipv4
				, (long int)addrss->ipv4_t.tv_sec
				, ipv6
				, (long int)addrss->ipv6_t.tv_sec) == -1)
	{
		warnx("Failed to asprintf output string");
		free(mac);
		free(ipv4);
		free(ipv6);
		return -1;
	}
	free(mac);
	free(ipv4);
	free(ipv6);
	return 0;
}

// and a header for the same
int asprint_clar_header(char** dest)
{
	if (asprintf(dest, "#   clarissa   "FORMAT_VERSION"\n") == -1)
	{
		warnx("Failed to asprint format header");
		return -1;
	}
	return 0;
}
