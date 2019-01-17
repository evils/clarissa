#include <stdio.h>
#include <err.h>

#include <pcap.h>


// get MAC and IP addresses out of a frame (first 66 bytes should have this)
struct addrss get_addrss(frame)
{
	struct addrss addrss;
	int offset = 0;

	// network to host byte order
	frame = ntohs(frame);

	// TODO
	// just get the head of the frame, assume it's right,
	// MAC will be unreachable and get purged
	// check if the IP is in the right range later?

	// doesn't match offsets in dsniff/pcaputil.c
	switch (pcap_datalink(frame))
	{
		case DLT_EN10MB:

			offset += 8;
			addrss.mac.source = get_mac(frame, offset);
			offset += 6;
			addrss.mac.dest = get_mac(frame, offset);

			// skip to payload
			offset += 8;

			// set offset based on payload type
			// get_eth_type() should take 802.1Q in mind
			// source IP address should be sufficient
			switch (get_eth_type(frame))
			{
				case IPv4:
					addrss.ipv = 4;
					offset += 12;
					addrss.ip_source.offset = offset;
					//offset += 7;
					//addrss.ip_dest.offset = offset;
					break;
				case ARP:
					addrss.ipv = 4;
					offset += 14;
					addrss.ip_source.offset = offset;
					//offset += 10;
					//addrss.ip_dest.offset = offset;
					break;
				case IPv6:
					addrss.ipv = 6;
					offset += 8;
					addrss.ip_source.offset = offset;
					//offset += 16;
					//addrss.ip_dest.offset = offset;
					break;
				default:
					warn ("unknown ethernet type");
					return -1;

					get_ip(frame, &addrss);
					return 0;
			}

		case DLT_IEEE802_11:

			switch (get_frame_type(frame))
			{
				case data_frame:
					addrss.mac.source = get_mac(frame,
					offset += 4);
					//addrss.mac.dest = get_mac(frame,
					//offset += 6);
					addrss.mac.tx_sta= get_mac(frame,
					offset += 6);
					//addrss.mac.rx_sta= get_mac(frame,
					//offset += 8);

				//TODO, other cases?

			}
	}
}

int main (int argc, char *argv[])
{


}
