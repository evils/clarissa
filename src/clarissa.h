#pragma once

#include "clarissa_defines.h"

#include <pcap.h>	// pcap everything duh
#include <netinet/in.h> // freebsd
#include <stdbool.h>	// type bool
#include <sys/stat.h>   // chmod

#include "time_tools.h"	// usec_diff()

int verbosity;

// extracted frame data
// this struct must be initialized to all zeros
struct Addrss
{
	// the found MAC address, and the time of capture
	// .mac is the only member that cannot remain all zeros
	uint8_t 	mac[6];	// source MAC address
	struct timeval	ts;	// MAC capture timestamp

	// save the latest v4 and v6 address
	// and the capture time of each
	struct timeval	ipv4_t;	// IPv4 capture time
	uint8_t 	ipv4[4];// latest IPv4 address
	struct timeval	ipv6_t;	// IPv6 capture time
	uint8_t 	ipv6[16];// latest IPv6 address

	// meta block, not present in the output
	bool		ip;	// true if an IP address was found
	bool		v6;	// true if that's an IPv6 address
	uint64_t	tags;	// packed VLAN tags (up to 5)
	uint16_t	tried;	// packets sent to this MAC
	struct Addrss*	next;	// pointer to next list entry
};

// values extracted from provided CIDR notation
struct Subnet
{
	// this doesn't use a literal mask because IPv6 masks are big
	// uses 16 bytes to accomodate either IPv6 or IPv4 mapped
	int	mask;		// number of masked bits
	uint8_t ip[16];		// base address for this subnet
};

// host (device) addresses
struct Host
{
	struct	Subnet subnet;	// subnet base addrss and mask
	uint8_t mac[6];		// MAC for ethernet frames
	uint8_t ipv6[16];	// IPv6 for NDP packets
	uint8_t ipv4[4];	// IPv4 for ARP packets
};

// a bunch of variables used in handle_opts() and elsewhere
struct Opts
{
	//pcap stuff
	char errbuf[PCAP_ERRBUF_SIZE];
	char* l_dev;		// name string for the listen device
	pcap_t* l_handle;	// listen handle from which we get frames
	char* s_dev;		// name string for the sending device
	pcap_t* s_handle;	// sending handle to which we send nag frames

	// clarissa stuff
	struct Subnet subnet;	// IPv4 subnet to filter by before nagging
	struct Host host;	// details of the interface being used
	int nags;		// how many times to nag a known MAC before culling it
	int timeout;		// hold-off time between receiving a frame and [nagging|culling]
	int interval;		// how often to run through the main loop
	int print_interval;     // how often to output the file
	char* print_filename;   // name of the output file
	char* socket;		// name of the output socket
	uint8_t cidr;		// how many subnets have been set (<=1 valid) by handle_opts()
	bool run;		// whether to run, 0 if just printing the header
	bool immediate;		// whether to pcap_set_immediate_mode
	bool promiscuous;	// whether to pcap_set_promisc on the listening interface
	bool will;		// whether to leave a will (file containing last list) at exit
	bool from_file;		// whether the current session is reading from a file
	bool socket_output;	// whether to output to a socket
};

// extraction
struct Addrss get_addrss
(pcap_t* handle, const uint8_t* frame, struct pcap_pkthdr* header);
int get_cidr(struct Subnet* dest, const char* cidr);
void get_if_mac(uint8_t* dest, const char* dev);
void get_if_ip(uint8_t* dest, const char* dev, int AF, char* errbuf);
void get_if_ipv4_subnet(struct Subnet* subnet, struct Opts* opts);
bool addrss_valid(const struct Addrss* addrss);

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
void print_ip(const uint8_t* ip, bool v6);
void asprint_ip(char** dest, const uint8_t* ip, bool v6);
void print_addrss(const struct Addrss* addrss);
int asprint_clar(char** dest, const struct Addrss* addrss);
int asprint_clar_header(char** dest);

// helpers
void subnet_filter(uint8_t* ip, const struct Subnet* subnet,
	const bool v6);
bool is_mapped(const uint8_t* ip);
bool is_zeros(const uint8_t* target, int count);
