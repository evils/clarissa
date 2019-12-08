#!/usr/bin/env sh

oui=clar_OUI.csv
tmp=".clar_scan_temp_file_delete_this.tmp"

if [ -z "$1" ]; then
	set $1 "$(echo /tmp/clar_*)"
fi

printf "Interface: %s\n" "$(echo "$1" | awk -F '_' '{print $2}')"
echo "Starting Clarissa output (https://gitlab.com/evils/clarissa)"

count=0;

while read -r; do
	ipv4="$(echo "$REPLY" | awk '{print $2}')"
	mac="$(echo "$REPLY" | awk '{print $1}')"
	vend_mac="$(echo "$REPLY" | tr -d ":-" | tr "a-f" "A-F" | awk '{print substr($1,1,6)}')"
	vendor="$(grep "$vend_mac" $oui | awk -F ',' '{print $2}' | sed 's/"//g' )"
	if [ -z "$vendor" ]; then vendor="(unknown)"; fi
	if [ "$ipv4" = "0.0.0.0" ]; then continue; fi
	printf "%s \t%s\t%s\n" "$ipv4" "$mac" "$vendor"
	count=$(( count + 1 ))
done < "$1" \
| sort | grep -v "0.0.0.0" | tee "$tmp"

count=$(wc -l "$tmp" | awk '{print $1}')
printf "\nEnding, %s responded" "$count"
clar=$(wc -l "$1" | awk '{print $1}')
diff=$(( clar - count ))
if [ "$diff" ]; then
	printf ", consider using \"clar show\", it has %s more result" "$diff"
	if [ "$diff" -gt 1 ]; then
		printf "s"
	fi
fi

echo

rm -f $tmp
