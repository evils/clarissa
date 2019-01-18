#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <err.h>
#include <pcap.h>

struct Addrss
{
	int		offset;		// stored here to pass to functions
	uint64_t	mac; 		// ETH source MAC
	uint64_t	mac_source;	// 802.11 source MAC
	uint64_t	mac_tx;		// 802.11 transmitting station MAC
	int		ipv;		// IPv4 or IPv6?
	uint64_t	ip_source;	// source IP (first half if IPv6)
	uint64_t	ipv6_second;	// source IP (second half if IPv6)
}


// get MAC and IP addresses out of a frame (first 66 bytes should have this?)
struct Addrss get_addrss(type_unknown frame)
{
	// network to host byte order
	// do this after pcap_datalink()?
	// this works on 16-32 bit uints?
	// TODO figure this out...
	frame = ntohs(frame);

	struct Addrss addrss;
	memset (&addrss, 0, sizeof(Addrss));

	// TODO
	// just get the head of the frame, assume it's right,
	// an invalid MAC will be unreachable and get purged
	// check if the IP is in the right range later?

	// link type is separately stored metadata?
	switch (pcap_datalink(&frame))
	{
		// doesn't match offsets in dsniff/pcaputil.c
		case DLT_EN10MB:

			addrss.offset += 14;
			get_mac(DLT_EN10MB, &frame, &addrss);

			// skip to payload
			addrss.offset += 8;

			// set offset based on payload type
			// get_eth_type() should take 802.1Q in mind
			// source IP address should be sufficient
			switch (get_eth_type(&frame, &addrss))
			{
				case IPv4:
					addrss.ipv = 4;
					offset += 12;
					get_ip(&frame, &addrss);
					break;
				case ARP:
					addrss.ipv = 4;
					offset += 14;
					get_ip(&frame, &addrss);
					break;
				case IPv6:
					addrss.ipv = 6;
					offset += 8;
					get_ip(&frame, &addrss);
					break;
				default:
					warn ("unknown ethernet type");
					return -1;
			}

			return 0;

		case DLT_IEEE802_11:

			switch (get_frame_type(frame))
			{
				case data_frame:
					addrss.offset += 4;
					// get source and tx station MAC (tx is offset +6)
					get_mac(DLT_IEEE802_11, &frame, &addrss);

				//TODO, other cases?
			}

			return 0;

		default:
			warn ("unsupported link type");
			return -1;
	}

	return 0;
}
// get every source address (MAC and IP) from every interface specified
int main (int argc, char *argv[])
{


}
