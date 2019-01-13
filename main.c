#include <pcap.h>


struct addrss get_addrss(packet){

struct addrss addrss;

	// doesn't match offsets in dsniff/pcaputil.c
	if pcap_datalink()==DLT_EN10MB {

		addrss.MAC1 = get_mac("eth", "source");
		addrss.MAC2 = get_mac("eth", "destination");

		// add offset for 802.11Q tag
		if is_1q() {
			offset += 4;
		}

		if ip(){

			addrss.IP1 = get_ip("eth", offset, "source");
			addrss.IP2 = get_ip("eth", offset, "destination");
		}
	}

	if pcap_datalink()==DLT_IEEE802_11 {

	}

}

int main (int argc, char *argv[]){


}
