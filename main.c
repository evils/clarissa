#include <stdio.h>
#include <err.h>

#include <pcap.h>


// get MAC and IP addresses out of a packet (first 66 bytes should have this)
struct addrss get_addrss(packet)
{
	struct addrss addrss;
	int offset = 0;

	// network to host byte order
	packet = ntohs(packet);

	// check packet validity
	// getting just 66 bytes may be more efficient but prohibits this
	if (invalid(packet))
	{
		warn ("found invalid packet");
		return -1;
	}

	// doesn't match offsets in dsniff/pcaputil.c
	switch (pcap_datalink(packet))
	{
		case DLT_EN10MB:

			offset += 8;
			addrss.mac.source = get_mac(packet, offset);
			offset += 6;
			addrss.mac.dest = get_mac(packet, offset);

			// add offset for 802.11Q tag
			if (is_1q(packet))
			{
				offset += 4;
			}

			// skip to payload
			offset += 8;

			// set offset based on payload type
			switch (get_eth_type(packet))
			{
				case IPv4:
					addrss.ipv = 4;
					offset += 12;
					addrss.ip_source.offset = offset;
					offset += 7;
					addrss.ip_dest.offset = offset;
					break;
				case ARP:
					addrss.ipv = 4;
					offset += 14;
					addrss.ip_source.offset = offset;
					offset += 10;
					addrss.ip_dest.offset = offset;
					break;
				case IPv6:
					addrss.ipv = 6;
					offset += 8;
					addrss.ip_source.offset = offset;
					offset += 16;
					addrss.ip_dest.offset = offset;
					break;
				default:
					warn ("unknown ethernet type");
					return -1;

					get_ip(packet, &addrss);
					return 0;
			}

		case DLT_IEEE802_11:

			switch (Get_frame_type(packet))
			{
				case data_frame:
					addrss.mac.source = get_mac(packet,
					offset += 4);
					addrss.mac.dest = get_mac(packet,
					offset += 6);
					addrss.mac.tx_sta= get_mac(packet,
					offset += 6);
					addrss.mac.rx_sta= get_mac(packet,
					offset += 8);

				//TODO, other cases?

			}

			// TODO get IP out of frame body
			// if it's the first of an IP sequence
			// Reuse the ethernet switch etc?

	}
}

int main (int argc, char *argv[])
{


}
