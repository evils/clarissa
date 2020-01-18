#!/usr/bin/env sh

oui=clar_OUI.csv

echo

if [ -z "$1" ]; then
	# shellcheck disable=SC2086
	set $1 "$(echo /tmp/clar_*)"
	echo "No input file specified."
	echo "Falling back on $1"
	echo
fi

echo "format is:"
# notices in parenthesis
# no spaces in individual strings
#   vendor string can't be helped
#   so put that on the end of a line!
printf "MAC\\tvendor\\n  IPv4\\t  domain\\t  IPv6\\n"
echo

printf "Interface: %s\\n" "$(echo "$1" | awk -F '_' '{print $2}')"
count=$(wc -l "$1" | awk '{print $1}')
printf "Clarissa found %s device" "$count"
if [ "$count" -gt 1 ]; then printf "s"; fi
printf "\\n\\n"

sort "$1" \
| while read -r "REPLY"; do
	mac="$(echo "$REPLY" | awk '{print $1}')"
	vend_mac="$(echo "$REPLY" | tr -d ":-" \
		| tr "a-f" "A-F" \
		| awk '{print substr($1,1,6)}')"
	vendor="$(grep "$vend_mac" $oui \
		| awk -F ',' '{print $2}' | sed 's/"//g' )"
	ipv4="$(echo "$REPLY" | awk '{print $2}')"
	ipv6="$(echo "$REPLY" | awk '{print $3}')"
	domain="$(dig -x "$ipv4" | grep "ANSWER SECTION" -A 1 \
		| awk '{print substr($5, 1, length($5)-1)}' \
		| sed '/^\s*$/d')"
	if [ -z "$domain" ]; then
		domain="$(dig -x "$ipv6" | grep "ANSWER SECTION" -A 1 \
			| awk '{print substr($5, 1, length($5)-1)}' \
			| sed '/^\s*$/d')"
	fi
	if [ -z "$domain" ]; then domain="(no_domain_found)"; fi
        if [ -z "$vendor" ]; then
                byte2="$(echo "$vend_mac" | cut -b 2)"
                result="$(( ( "$byte2" / 2 ) % 2 ))"
                if [ "$result" -eq 1 ]; then
                        vendor="$(printf "(Locally_Administered_Address)")"
		else
                        vendor="$(printf "(vendor_not_listed_(UAA))")"
                fi
        fi
	printf "%s\\t%s\\n" "$mac" "$vendor"
	printf "  %s\\t\\t" "$ipv4"
	if [ "$domain" ]; then
		printf "  %s" "$domain"
		# shellcheck disable=SC2000
		if [ "$(echo "$domain" | wc -c)" -le 12 ]; then
			printf "\\t"
		fi
	else printf "\\t\\t"
	fi
	printf "\\t  %s\\n" "$ipv6"
done

echo
