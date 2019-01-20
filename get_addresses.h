#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <pcap.h>

// ethernet types
#define IPv4 0x0800
#define IPv6 0x86DD
#define ARP 0x806

// 802.11 frame types
#define DOT11_DATA 0xBAD

struct Addrss get_addrss(pcap_t frame);
int get_frame_type(void* frame, struct Addrss* addrss);
int get_mac(void* frame, struct Addrss* addrss);
int get_ip(void* frame, struct Addrss* addrss);

struct Addrss
{
	int	link_type;	// output of pcap_datalink()
        int     offset;         // stored here to pass to functions
        union ip		// IPv4 or IPv6 address
        {
                uint8_t v4[4];
                uint8_t v6[16];
        }
        source;
        uint8_t mac[6];         // ETH source MAC
        uint8_t mac_source[6];  // 802.11 source MAC
        uint8_t mac_tx[6];      // 802.11 transmitting station MAC

        //uint64_t      mac;            // ETH source MAC
        //uint64_t      mac_source;     // 802.11 source MAC
        //uint64_t      mac_tx;         // 802.11 transmitting station MAC
        //int           ipv;            // IPv4 or IPv6?
        //uint64_t      ip_source;      // source IP (first half if IPv6)
        //uint64_t      ipv6_second;    // source IP (second half if IPv6)
};
