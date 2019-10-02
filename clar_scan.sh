#/usr/bin/env sh

echo

TALLY=0

while read -r; do
	ip="$(echo $REPLY | awk '{print $2}')"
	mac="$(echo $REPLY | awk '{print $1}')"
	vend_mac="$(echo $REPLY | tr -d ":-" | tr [a-f] [A-F] | awk '{print substr($1,1,6)}')"
	vendor="$(grep $vend_mac oui.txt | awk '{ s = ""; for (i = 4; i <= NF; i++) s = s $i " "; print s }')"
	if [ -z "$vendor" ]; then vendor="(unknown)"; fi
	printf " $ip\t\t\t\t$mac\t$vendor\n"
	(( TALLY++ ))
done < "$1"

printf "\n found $TALLY devices\n\n"
