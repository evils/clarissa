# Clarissa
[Clarissa](https://gitlab.com/evils/clarissa) is a daemon which keeps a list of all connected devices on a network.
## Values
Clarissa is an attempt at replacing [Pamela](https://github.com/sandb/pamela)'s scanner with something that does not rely on scanning the entire network every so often.

The design goals are an ability to run **quietly** (without sending out packets at all), have better time resolution (arp-scan can trigger rate limiting) and make the **output** available locally.

* Running **quietly** imposes a practical minimum **timeout** of the longest time between packets for any device you want to keep track of.
* Better time resolution can be obtained by **nagging** devices.
* The **output** is a regularly updated plain file (**/tmp/clar\_[dev]\_[subnet]-[mask]** by default).

## Concept
* When a MAC address is found in a frame on the **listen** interface, it is saved along with a timestamp as an entry in an internal list.
	* If this entry is already on the list, the timestamp is updated.
	* Using **Promiscuous** mode can significantly increase the amount of packets seen and reduce the need to **nag**.
* Clarissa uses their timestamp and a set **timeout** to determine when to **nag** entries.
	* When an entry has been **nagged** a set number of times, it is removed from the list on the next **interval**.
	* If an IPv4 or v6 address was found, an entry gets **nagged** via ARP or NDP respectively.
* The output file contains the MAC addresses (one per line), along with their latest IP [v4|v6] addresses, if present, tab separated.

## Options

<pre>
Long		Short

--help		-h
	show the help message
--header	-H
	show the Header and exit
--verbose	-v
	increase verbosity (shows 0 = err & warn < MAC < IP < chatty < debug < vomit)
--version	-V
	show the Version
--<b>quiet</b>		-q
	Quiet, send out no packets (equivalent to -n 0)
--<b>promiscuous</b>	-p
	set the interface to Promiscuous mode
--unbuffered	-u
	don't buffer packets (use immediate mode)
</pre>

### Requiring an argument:

<pre>
--interface	-I
	set the primary Interface
--listen	-l
	set the <b>Listen</b>ing interface
--interval	-i
	set the interval (in milliseconds)
--<b>nags</b>		-n
	set the number of times to "Nag" a target
--<b>timeout</b>	-t
	set the Timeout for an entry (wait time for nags in ms)
--subnet	-s
	get a Subnet to filter by (in CIDR notation)
--file		-f
	File input (pcap file, works with - (stdin))
--<b>output_file</b>	-o
	set the output filename
--output_interval	-O
	set the Output interval
</pre>

## Packages
The latest packages may be found [here](https://evils.eu/clarissa/packages/).
