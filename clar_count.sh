#!/usr/bin/env bash

# get the count of MAC addresses' named in the macs.csv ($1) for all the found MAC addresses ($2)
# and output a count of the unique names (minus those with "(nc)") and tally of the remaining addresses
# in a variety of formats (specified by $3)

# the format options are:
# -c or --csv, CSV with header (accepted by telegraf (for influxdb))
# -t or --title, short CSV showing the count of known entities and everything else
# -j or --json, json format (accepted by telegraf (for influxdb))
# -i or --influx, influx line protocol (accepted by telegraf (for influxdb))
# -n or --names, show all names minus "hidden"


# maybe set this to measurement's location? (useful for influxdb)
NAME="clarissa"

# show correct usage if used incorrectly
if [ -z "$3" ]; then
echo "Please use the following format:"
echo "clar_count.sh [path to macs.csv] [path to clarissa's output] [option (-a for all)]"
fi

# do the actual counting

NAMES=()
TALLY=0

while read -r; do
	LINE=$(grep "$REPLY" "$1")
	if [ "$LINE" ]; then
		NAMES+=("$(echo "$LINE" | awk -F "," '{print $2}')" )
	else
		let "TALLY++"
	fi
done < "$2"

COUNT=$(printf '%s\n' "${NAMES[@]}" | grep -v "(nc)" | sort | uniq | sed '/^\s*$/d' | wc -l)


# formatted counts as:

csv() {
        echo "name,counted,balance"
	echo "$NAME"",""$COUNT"",""$TALLY"
}

title() {
	echo "$COUNT"",""$TALLY"
}

json() {
echo "{\"name\":\"""$NAME""\", \"counted\":""$COUNT"", \"balance\":""$TALLY""}"
}

influx() {
echo "$NAME"" counted=""$COUNT"",balance=""$TALLY"
}

names_json() {
names | jq -csR '[ split ("\n") | .[] | select(length > 0)]'
}

names() {
printf '%s\n' "${NAMES[@]}" | grep -v "hidden" | sed -e 's/(nc)//' | sort | uniq
}


# handle the options

case "$3" in

        -c|--csv) csv ;;

        -t|--title) title ;;

        -j|--json) json ;;

        -i|--influx) influx ;;

	-n|--names) names ;;

	-nj|-jn|--names_json) names_json ;;

        # for testing
        -a|--all) csv; printf "\n"; title; printf "\n";  json; printf "\n"; influx; printf "\n"; names_json; printf "\n"; names ;;

        *) exit 1 ;;
esac


# the format of macs.csv should be:
# MAC address,name
# MAC address,hidden
# MAC address,name(nc)
# MAC address,hidden(nc)

# any lines without a MAC address won't get used and any fields after the name will be ignored
# additionally, any address named "hidden" will not be shown by names()
# and any name containing "(nc)" will not be counted in $COUNT

# NOTE, while having an empty field for the "name" column currently has the same effect as "hidden(nc)", this could be subject to change
