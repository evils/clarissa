#!/usr/bin/env sh

echo

if [ -z "$1" ]; then
	echo "No input file specified."
	set $1 "$(echo /tmp/clar_*)"
	echo "Falling back on $1"
	echo
fi

while read -r; do
	ip="$(echo "$REPLY" | awk '{print $2}')"
	mac="$(echo "$REPLY" | awk '{print $1}')"
	vend_mac="$(echo "$REPLY" | tr -d ":-" | tr "a-f" "A-F" | awk '{print substr($1,1,6)}')"
	vendor="$(grep "$vend_mac" oui.txt | cut -f 3- )"
	if [ -z "$vendor" ]; then vendor="(unknown)"; fi
	printf " %s\t%s\n" "$mac" "$vendor"
	if [ "$ip" ]; then printf " %s\n\n" "$ip"; fi
done < "$1"

echo
