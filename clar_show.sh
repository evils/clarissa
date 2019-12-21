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
printf "MAC\tvendor\n  IPv4\t  domain\t  IPv6\n"
echo

printf "Interface: %s\n" "$(echo "$1" | awk -F '_' '{print $2}')"
count=$(wc -l "$1" | awk '{print $1}')
printf "Clarissa found %s device" "$count"
if [ $count -gt 1 ]; then printf "s"; fi
printf "\n\n"

while read -r; do
	mac="$(echo "$REPLY" | awk '{print $1}')"
	vend_mac="$(echo "$REPLY" | tr -d ":-" | tr "a-f" "A-F" | awk '{print substr($1,1,6)}')"
	vendor="$(grep "$vend_mac" $oui | awk -F ',' '{print $2}' | sed 's/"//g' )"

	ipv4="$(echo "$REPLY" | awk '{print $2}')"
	ipv6="$(echo "$REPLY" | awk '{print $3}')"
	domain="$(dig -x "$ipv4" | grep "ANSWER SECTION" -A 1 | awk '{print substr($5, 1, length($5)-1)}' | sed '/^\s*$/d')"

	if [ -z "$vendor" ]; then vendor="(unknown)"; fi
	printf "%s\t%s\n" "$mac" "$vendor"
	printf "  %s\t\t" "$ipv4"
	if [ "$domain" ]; then
		printf "  %s" "$domain"
		if [ $(echo "$domain" | wc -c) -le 12 ]; then
			printf "\t"
		fi
	else printf "\t\t"
	fi
	printf "\t  %s\n" "$ipv6"
done < "$1"

echo
