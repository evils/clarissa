#!/bin/sh

oui=clar_OUI.csv
clar=$(command -v ./clarissa || command -v clarissa || command -v "${dir}"/clarissa)

echo

if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
	echo "format is:"
	# notices in parenthesis
	# no spaces in individual strings
	#   vendor string can't be helped
	#   so put that on the end of a line!
	printf "MAC\\tvendor\\n  IPv4\\t  domain\\t  IPv6\\n"
	echo
	shift 1
fi

if [ ! -f "$oui" ]; then
	echo "WARNING: No OUI file, try OUI_assemble.sh?"
fi

# cat outputs some headers starting with #
# one of those is a version header
# probably should check that for compatibility...
c_cat() {
	dir="$(cd "$(dirname "$0")" && pwd -P)"
	"${clar}" cat "$@" | grep -v "#"
}

printf "Interface: %s\\n" "$(echo "$1" | awk -F '[/_]' '{print $4}')"
count=$(c_cat "$@" | wc -l | awk '{print $1}')
printf "Clarissa found %s device" "$count"
if [ "$count" -gt 1 ]; then printf "s"; fi
printf "\\n\\n"

c_cat "$@" | sort \
| while read -r "REPLY"; do
	mac="$(echo "$REPLY" | awk '{print $1}')"
	vend_mac="$(echo "$mac" | tr -d ":-" \
		| tr "a-f" "A-F" \
		| awk '{print substr($1,1,6)}')"
	vendor="$(grep -s "$vend_mac" "$oui" \
		| awk -F ',' '{print $2}' | sed 's/"//g' )"
	ipv4="$(echo "$REPLY" | awk '{print $3}')"
	ipv6="$(echo "$REPLY" | awk '{print $5}')"
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
		result="$(( ( byte2 / 2 ) % 2 ))"
		if [ "$result" -eq 1 ]; then
			vendor="$(printf "(Locally_Administered_Address)")"
		else
			vendor="$(printf "(vendor_not_listed_(UAA))")"
		fi
	fi
	printf "%s\\t%s\\n" "$mac" "$vendor"
	printf "  %s\\t\\t" "$ipv4"
	if [ -n "$domain" ]; then
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
