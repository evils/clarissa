#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <pcap.h>
#include <sys/time.h>

// ethernet types
#define IPv4 0x0800
#define IPv6 0x86DD
#define ARP 0x806
#define DOTQ 0x8100
#define DOTAD 0X88A8
#define DOUBLETAG 0x9100
#define ETH_SIZE 0x600

struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header);
int get_eth_protocol(const uint8_t* frame, struct Addrss* addrss);
int dot1_extend(const uint8_t* frame, struct Addrss* addrss);
int addrss_list_update(struct Addrss* head, struct Addrss new_addrss);
int print_mac(struct Addrss* addrss);

struct Addrss
{
	struct timeval	cap_time;	// time this frame was captured
	uint8_t ip[16];			// IPv6 and mapped IPv4
        uint8_t mac[6];			// source MAC
        int     offset;			// stored here to pass to functions
	struct Addrss*	next;		// pointer to next element in list
};
