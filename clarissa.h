#pragma once

// for asprintf() (clarissa internal...)
#define _GNU_SOURCE

#include <pcap.h>	// pcap everything duh

#include "time_tools.h"	// usec_diff()

int verbosity;

// extracted frame data
struct Addrss
{
	struct pcap_pkthdr	header;	// pcap metadata for this capture
	uint8_t 		ipv4[4];// latest IPv4 address
	uint8_t 		ip[16];	// latest IPv6 or mapped IPv4 address
	uint8_t 		mac[6];	// source MAC
	uint64_t		tags;	// VLAN tags (up to 5)
	uint16_t		tried;	// number of packets sent to target
	struct Addrss*		next;	// pointer to next element in list
};

// values extracted from provided CIDR notation
struct Subnet
{
	// this doesn't use the mask directly because IPv6 masks are big
	int	mask;		// number of masked bits
	uint8_t ip[16];		// base address for this subnet
};

// host (device) addresses
struct Host
{
	struct	Subnet ipv4_subnet;	// subnet base address and mask
	uint8_t mac[6];			// MAC for ethernet frames
	uint8_t ipv6[16];		// IPv6 for NDP packets
	uint8_t ipv4[16];		// IPv4 for ARP packets (mapped on IPv6 for ease of use)
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
	int run;
	int immediate;
};

// extraction
struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header);
int get_cidr(struct Subnet* dest, const char* cidr);
void get_if_mac(uint8_t* dest, const char* dev);
void get_if_ip(uint8_t* dest, const char* dev, int AF, char* errbuf);
void get_if_ipv4_subnet(struct Subnet* subnet, struct Opts* opts);

// list
void addrss_list_add(struct Addrss** head, const struct Addrss* new_addrss);
void addrss_list_cull(struct Addrss** head, const struct timeval* ts,
	const int timeout, const int nags);
void addrss_list_nag(struct Addrss** head, const struct timeval* ts,
	const int timeout, const struct Opts* opts, uint64_t* count);

// output
void dump_state(char* filename, struct Addrss *head);
void print_mac(const uint8_t* mac);
void asprint_mac(char** dest, const uint8_t* mac);
void print_ip(const uint8_t* ip);
void asprint_ip(char** dest, const uint8_t* ip);

// misc
void subnet_filter(uint8_t* ip, struct Subnet* mask);
