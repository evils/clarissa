# Clarissa
[Clarissa](https://gitlab.com/evils/clarissa) is a daemon which keeps a list of all connected devices on a network.
## Values
Clarissa is an attempt at replacing [Pamela](https://github.com/sandb/pamela)'s scanner with something that does not rely on scanning the entire network every so often.

The design goals are an ability to run **quietly** (without sending out packets at all), have better time resolution (arp-scan can trigger rate limiting) and make the **output** available locally.

* Running **quietly** imposes a practical minimum **timeout** of the longest time between packets for any device you want to keep track of.
* Better time resolution can be obtained by **nagging** devices.
* The **output** is a regularly updated plain file (**/tmp/clar\_[dev]\_[subnet]-[mask]** by default).

## Concept
* When a MAC address is found in a frame on an **interface**, it is saved along with a timestamp as an entry in an internal list.
	* If this entry is already on the list, the timestamp is updated.
	* Using **Promiscuous** mode can significantly increase the amount of packets seen and reduce the need to **nag**.
* Clarissa uses their timestamp and a set **timeout** to determine when to **nag** entries.
	* When an entry has been **nagged** a set number of times, it is removed from the list on the next **interval**.
	* If an IPv4 or v6 address was found, an entry gets **nagged** via ARP or NDP respectively.
* The output only contains the MAC addresses (one per line), as an IP address is not guaranteed to be present for any entry.

## Options

<pre>
--help or -h
	show the help message
--header or -H
	show the Header and exit
--verbose or -v
	increase Verbosity (shows 0 = err & warn < MAC < IP < chatty < debug < vomit)
--<b>quiet</b> or -q
	Quiet, send out no packets (equivalent to -n 0)
--<b>promiscuous</b> or -p
	set the interface to Promiscuous mode
</pre>

### Requiring an argument:

<pre>
--<b>interface</b> or -I
	set the Interface used. If set to "any", -n 0 is forced
--interval or -i
	set the interval (in milliseconds)
--<b>nags</b> or -n
	set the number of times to "Nag" a target
--<b>timeout</b> or -t
	set the Timeout for an entry (wait time for nags in ms)
--subnet or -s
	get a Subnet to filter by (in CIDR notation)
--file or -f
	File input (pcap file, works with - (stdin)), forces -n 0
--<b>output_file</b> or -o
	set the output filename
--output_interval or -O
	set the Output interval
</pre>

## Packages
The latest packages may be found [here](https://evils.eu/clarissa/packages/).
