#!/usr/bin/env sh

oui=clar_OUI.csv

echo

if [ -z "$1" ]; then
	set $1 "$(echo /tmp/clar_*)"
	echo "No input file specified."
	echo "Falling back on $1"
	echo
fi

echo "format is:"
printf "MAC\tVendor\n  IPv4\t  IPv6\n"
echo

printf "Interface: %s\n" "$(echo "$1" | awk -F '_' '{print $2}')"
count=$(wc -l "$1" | awk '{print $1}')
printf "Clarissa found %s device" "$count"
if [ $count -gt 1 ]; then printf "s"; fi
printf "\n\n"

while read -r; do
	ipv6="$(echo "$REPLY" | awk '{print $3}')"
	ipv4="$(echo "$REPLY" | awk '{print $2}')"
	mac="$(echo "$REPLY" | awk '{print $1}')"
	vend_mac="$(echo "$REPLY" | tr -d ":-" | tr "a-f" "A-F" | awk '{print substr($1,1,6)}')"
	vendor="$(grep "$vend_mac" $oui | awk -F ',' '{print $2}' | sed 's/"//g' )"
	if [ -z "$vendor" ]; then vendor="(unknown)"; fi
	printf "%s\t%s\n" "$mac" "$vendor"
	printf "  %s\t\t  %s\n" "$ipv4" "$ipv6"
done < "$1"

echo
