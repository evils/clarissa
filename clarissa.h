#pragma once
#define _GNU_SOURCE

#include <stdlib.h>	// exit(), free(), strtol()
#include <string.h>	// mem*(), strn*()
#include <err.h>	// warn()
#include <pcap.h>	// pcap everything duh
#include <arpa/inet.h>	// inet_pton(), struct sockaddr_in
#include <sys/ioctl.h>	// ioctl(), SIOCGIFADDR
#include <net/if.h>	// struct ifreq, IFNAMSIZ
#include <unistd.h>	// close()
#include <net/if_arp.h>	// ARPHRD_ETHER
#include <stdio.h>	// asprintf()
#include <sys/stat.h>	// chmod

#include "time_tools.h"	// usec_diff()

int verbosity;

// ethernet types
#define IPv4 0x0800
#define IPv6 0x86DD
#define ARP 0x0806
#define DOT1Q 0x8100
#define DOT1AD 0X88A8
#define DOT1QINQ 0x9100
#define ETH_SIZE 0x0600
#define ARUBA_AP_BC 0x8ffd
#define EAPOL 0x888e
#define DOT11R 0x890d

// extracted frame data
struct Addrss
{
	struct pcap_pkthdr	header;	// pcap metadata for this capture
	uint8_t 		ip[16];	// IPv6 and mapped IPv4
	uint8_t 		mac[6];	// source MAC
	uint64_t		tags;	// VLAN tags (up to 5)
	uint8_t			tried;	// number of packets sent to target
	struct Addrss*		next;	// pointer to next element in list
};

// values extracted from provided CIDR notation
struct Subnet
{
	// this doesn't use the mask directly because IPv6 masks are big
	int	mask;		// number of masked bits
	uint8_t ip[16];		// base address for this subnet
};

// host addresses
struct Host
{
	struct	Subnet ipv4_subnet;	// subnet base address and mask
	uint8_t mac[6];			// MAC for ethernet frames
	uint8_t ipv6[16];		// IPv6 for NDP packets
	uint8_t ipv4[16];		// IPv4 for ARP packets
};

// a bunch of variables used in handle_opts() and elsewhere
struct Opts
{
	//pcap stuff
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	char* dev;

	// clarissa stuff
	struct Subnet subnet;
	struct Host host;
	int timeout;
	int interval;
	int print_interval;
	char* print_filename;
	int nags;
	int promiscuous;
	int cidr;
};

// extraction
struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header);
int get_tag(const uint8_t* frame, struct Addrss* addrss);
int get_eth_ip(const uint8_t* frame, struct Addrss* addrss,
		const uint16_t type);
int get_cidr(struct Subnet* dest, const char* cidr);
void get_if_mac(uint8_t* dest, const char* dev);
void get_if_ip(uint8_t* dest, const char* dev, int AF, char* errbuf);
void get_if_ipv4_subnet(struct Subnet* subnet, struct Opts* opts);
// helpers
int is_zeros(const uint8_t* target, int count);
int is_mapped(const uint8_t* ip);
void subnet_check(uint8_t* ip, struct Subnet* mask);
int bitcmp(uint8_t* a, uint8_t* b, int n);

// list
void addrss_list_add(struct Addrss** head, const struct Addrss* new_addrss);
void addrss_list_cull(struct Addrss** head, const struct timeval* ts,
			const int timeout, const int nags);
void addrss_list_nag(struct Addrss** head, const struct timeval* ts,
			const int timeout, const struct Opts* opts);

// network output
void nag(const struct Addrss* addrss, const struct Opts* opts);
void send_arp(const struct Addrss* addrss, const struct Opts* opts);
void send_ndp(const struct Addrss* addrss, const struct Opts* opts);
// helpers
void fill_eth_hdr
(uint8_t* frame, int* ptr,
	const struct Addrss* addrss, const struct Opts* opts);
void net_put_u16(uint8_t* target, uint16_t source);
void net_put_u32(uint8_t* target, uint32_t source);
uint16_t inet_csum_16(uint8_t* addr, int count, uint16_t start);

// other output
void dump_state(char* filename, struct Addrss *head);
void print_mac(const uint8_t* mac);
void print_ip(const uint8_t* ip);
