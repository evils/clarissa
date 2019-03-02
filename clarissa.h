#pragma once

#include <stdlib.h>	// exit(), free(), strtol()
#include <string.h>	// mem*(), strn*()
#include <err.h>	// warn()
#include <pcap.h>	// pcap everything duh
#include <arpa/inet.h>	// inet_pton(), struct sockaddr_in
#include <sys/ioctl.h>	// ioctl(), SIOCGIFADDR
#include <net/if.h>	// struct ifreq, IFNAMSIZ
#include <unistd.h>	// close()
#include <net/if_arp.h>	// ARPHRD_ETHER

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

// host addresses
struct Host
{
	uint8_t mac[6];		// MAC for ethernet frames
	uint8_t ipv6[16];	// IPv6 for NDP packets
	uint8_t ipv4[4];	// IPv4 for ARP packets
};

// values extracted from provided CIDR notation
struct Subnet
{
	int	mask;		// number of masked bits
	uint8_t ip[16];		// base address for this subnet
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
        int nags;
        int promiscuous;
        int parsed;
};

struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header);
int get_tag(const uint8_t* frame, struct Addrss* addrss);
int get_eth_ip(const uint8_t* frame, struct Addrss* addrss, uint16_t type);
int addrss_list_add(struct Addrss** head, struct Addrss* new_addrss);
int addrss_list_cull
(struct Addrss** head, struct timeval* ts, int timeout, int nags);
int addrss_list_nag
(struct Addrss** head, struct timeval* ts, int timeout, struct Opts* opts);
void print_mac(uint8_t* mac);
void print_ip(uint8_t* ip);
int nag(struct Addrss* addrss, struct Opts* opts);
int subnet_check(uint8_t* ip, struct Subnet* mask);
int parse_cidr(char* cidr, struct Subnet* dest);
int get_mac(uint8_t* dest, char* dev);
int get_ipv4(uint8_t* dest, char* dev);
//int get_ipv6(uint8_t* dest, char* dev);
void net_puts(uint8_t* target, uint16_t source);
