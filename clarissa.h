#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <pcap.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "time_tools.h"

// ethernet types
#define IPv4 0x0800
#define IPv6 0x86DD
#define ARP 0x806
#define DOTQ 0x8100
#define DOTAD 0X88A8
#define DOUBLETAG 0x9100
#define ETH_SIZE 0x600

// time to wait before querying a target (in microseconds (µs))
#define TIMEOUT 5000000
// number of times to query a target before dropping them from the list
#define TRIES 3

// extracted frame data
struct Addrss
{
	struct pcap_pkthdr	header;	// pcap metadata for this capture
	uint8_t 	ip[16];		// IPv6 and mapped IPv4
	uint8_t 	mac[6];		// source MAC
	uint64_t	tags;		// VLAN tags (up to 5)
	uint8_t		tried;		// number of packets sent to target
	struct Addrss*	next;		// pointer to next element in list
};

// values extracted from provided CIDR notation
struct Netmask
{
	int		mask;		// number of masked bits
	uint8_t 	ip[16];		// base address for this subnet
};

struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header);
int get_tag(const uint8_t* frame, struct Addrss* addrss);
int get_eth_ip(const uint8_t* frame, struct Addrss* addrss, uint16_t type);
int addrss_list_update(struct Addrss** head, struct Addrss new_addrss);
int print_mac(struct Addrss* addrss);
int print_ip(struct Addrss* addrss);
int query(struct Addrss* addrss);
int ip_check(uint8_t* ip);
int parse_cidr(char* cidr, struct Netmask* dest);
