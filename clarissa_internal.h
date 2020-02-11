#pragma once

#include <stdlib.h>     // free(), strtol()
#include <err.h>        // warn()
#include <string.h>     // mem*(), strn*()
#include <arpa/inet.h>  // inet_pton(), struct sockaddr_in
#include <sys/ioctl.h>  // ioctl(), SIOCGIFADDR
#include <net/if.h>     // struct ifreq, IFNAMSIZ
#include <unistd.h>     // close()
#include <net/if_arp.h> // ARPHRD_*
#include <stdio.h>      // asprintf()
#include <sys/stat.h>   // chmod

#include "get_hardware_address/get_hardware_address.h"

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

// extraction
int get_tag(const uint8_t* frame, intptr_t max, struct Addrss* addrss);
int get_eth_ip(const uint8_t* frame, intptr_t max, struct Addrss* addrss,
		const uint16_t type);

// helpers
bool is_zeros(const uint8_t* target, int count);
bool is_mapped(const uint8_t* ip);
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
