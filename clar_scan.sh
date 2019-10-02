#/usr/bin/env bash

echo

TALLY=0

while read -r; do
	mac="$(echo $REPLY | tr -d ":-" | awk '{toupper($1); print substr($1,1,6)}')"
	vendor="$(grep $mac oui.txt | awk '{ s = ""; for (i = 4; i <= NF; i++) s = s $i " "; print s }')"
	printf " $REPLY"
	if [ "$vendor" ]; then
		printf "\t\t\t$vendor\n"
		(( TALLY++ ))
	fi
done < "$1"

printf "\n found $TALLY devices\n\n"
