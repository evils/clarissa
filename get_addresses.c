#include "get_addresses.h"

// get MAC and IP addresses out of a frame (first 54 bytes should have this?)
struct Addrss get_addrss(pcap_t frame)
{
        // network to host byte order
        // do this after pcap_datalink()?
        // this works on 16-32 bit uints?
        // TODO figure this out...
        //frame = ntohs(frame);

        struct Addrss addrss;
        memset (&addrss, 0, sizeof(addrss));

        // TODO
        // use just the head of the frame, assume it's right,
        // an invalid MAC will be unreachable and get purged
        // check if the IP is in the right range later?

        // link type is separately stored metadata?
	addrss.link_type = pcap_datalink(&frame);
        switch (addrss.link_type)
        {
                // doesn't match offsets in dsniff/pcaputil.c
                case DLT_EN10MB:

                        addrss.offset += 14;
                        get_mac(&frame, &addrss);

                        // skip to payload
                        addrss.offset += 8;

                        // set offset based on payload type
                        switch (get_frame_type(&frame, &addrss))
                        {
                                case IPv4:
                                        addrss.offset += 12;
                                        get_ip(&frame, &addrss);
                                        break;
                                case ARP:
                                        addrss.offset += 14;
                                        get_ip(&frame, &addrss);
                                        break;
                                case IPv6:
                                        addrss.offset += 8;
                                        get_ip(&frame, &addrss);
                                        break;
                                default:
                                        warn ("unknown ethernet type");
					exit(1);
                        }

                        return addrss;

                // TODO
                // 802.11 is more complex, TBD
                // most of this is incorrect, only here for reference
                case DLT_IEEE802_11:

                        switch (get_frame_type(&frame, &addrss))
                        {
                                case DOT11_DATA:
                                        addrss.offset += 4;
                                        // get source and tx station MAC
                                        get_mac
					(&frame, &addrss);

                                //TODO, other cases?
                        }

                        return addrss;

                default:
                        warn ("unsupported link type");
			exit(1);
        }

        return addrss;
}


// return frame type for ethernet 802.11 and adjust offset in struct addrss
int get_frame_type(void* frame, struct Addrss* addrss)
{
	// TODO

	// TODO, account for 802.1Q

        return 0;
}

// get the MAC address(es) out of the frame of link_type and store in struct
int get_mac(void* frame, struct Addrss* addrss)
{
	// TODO

        return 0;
}

int get_ip(void* frame, struct Addrss* addrss)
{
	// TODO

        return 0;
}
