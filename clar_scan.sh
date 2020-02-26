#!/usr/bin/env sh

oui=clar_OUI.csv
tmp=".clar_scan_temp_file_delete_this.tmp"

c_cat() {
       dir="$(cd "$(dirname "$0")" && pwd -P)"
       ${dir}/clarissa cat $1 | grep -v "#"
}

if [ -z "$1" ]; then
	# shellcheck disable=SC2086
	set $1 "$(echo /var/run/clar/*)"
fi

if [ ! -f "$oui" ]; then
	echo "WARNING: No OUI file, try OUI_assemble.sh?"
fi

printf "Interface: %s\\n" "$(echo "$1" | awk -F '[/_]' '{print $4}')"
echo "Starting Clarissa output (https://gitlab.com/evils/clarissa)"

count=0;

c_cat | sort | grep -sv "0.0.0.0" | tee "$tmp" \
| while read -r "REPLY"; do
	ipv4="$(echo "$REPLY" | awk '{print $2}')"
	mac="$(echo "$REPLY" | awk '{print $1}')"
	vend_mac="$(echo "$mac" | tr -d ":-" | tr "a-f" "A-F" | awk '{print substr($1,1,6)}')"
	vendor="$(grep -s "$vend_mac" "$oui" | awk -F ',' '{print $2}' | sed 's/"//g' )"
	if [ -z "$vendor" ]; then
		vendor="(Unknown"
		byte2="$(echo "$vend_mac" | cut -b 2)"
		result="$(( ( "$byte2" / 2 ) % 2 ))"
		if [ "$result" -eq 1 ]; then
			vendor="$(printf "%s: locally administered" "$vendor")"
		fi
		vendor="$(printf "%s)" "$vendor")"
	fi
	if [ "$ipv4" = "0.0.0.0" ]; then continue; fi
	printf "%s \\t%s\\t%s\\n" "$ipv4" "$mac" "$vendor"
	count=$(( count + 1 ))
done

count=$(wc -l "$tmp" | awk '{print $1}')
printf "\\nEnding, %s responded, consider using \"clarissa show\"" "$count"
clar=$(c_cat | wc -l | awk '{print $1}')
diff=$(( clar - count ))
if [ "$diff" -gt 0 ]; then
	printf ", it has %s more result" "$diff"
	if [ "$diff" -ne 1 ]; then
		printf "s"
	fi
fi

echo

rm -f "$tmp"
