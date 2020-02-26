#!/usr/bin/env bash

# get the count of MAC addresses named in the macs.csv ($1) for all the found MAC addresses ($2)
# and output a count of the unique names (minus those with "?") and tally of the remaining addresses
# and provide a list of those names (minus those with "!")
# in a variety of formats (specified by $3)

# the format options are:
# -c or --csv, CSV with header (accepted by telegraf (for influxdb))
# -t or --title, short CSV showing the count of known entities and everything else
# -j or --json, json format (accepted by telegraf (for influxdb))
# -i or --influx, influx line protocol (accepted by telegraf (for influxdb))
# -n or --names, show all names minus those with an exclamation mark "!"
# -nj or --names_json, same as --names but in a json array


# maybe set this to measurement's location? (useful for influxdb)
NAME="clarissa"

c_cat() {
        dir="$(cd "$(dirname "$0")" && pwd -P)"
        ${dir}/clarissa cat $1 | grep -v "#"
}

# show correct usage if used incorrectly
if [ -z "$3" ]; then
echo "Please use the following format:"
echo "count [path to macs.csv] [path to clarissa's output] [option (-a for all)]"
fi

# do the actual counting

NAMES=()
TALLY=0

while read -r "REPLY"; do
	LINE="$(grep -i "$(echo "$REPLY" | awk '{print $1}')" "$1")"
	if [ -n "$LINE" ]; then
		NAMES+=("$(echo "$LINE" | awk -F "," '{print $2}')" )
	else
		(( TALLY++ ))
	fi
# can't pipe in from the front because of TALLY's scope
done <<< $(c_cat)

COUNT="$(printf '%s\n' "${NAMES[@]}" | sed -e '/^\s*$/d' -e '/[?‽]/d' | sort | uniq | wc -l)"


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
printf '%s\n' "${NAMES[@]}" | sed -e 's/?//g' -e '/[!‽]/d' | sort | uniq
}

# log the number of unique devices seen during a running instance of this function
log() {

salt_n=420
if [ -z "$2" ]; then
	salt="$(head -c "$salt_n" /dev/urandom | hexdump -v)"
	echo "Using random salt of length: ${salt_n}"
else
	salt="$(echo "$2" | hexdump -v)"
	echo "Using salt: ${salt}"
fi

log=~/clar_"$(date +%s)".log

echo
echo "Session unique hashes stored in ${log}"

while true; do

	while read -r "REPLY"; do

		echo "$REPLY" "$salt" | sha256sum >> "$log"

	done < "$1"

	sort "$log" | uniq > "${log}.tmp"
	mv "${log}.tmp" "$log"

	sleep 60

done

}


# handle the options

case "$3" in

	-c|--csv) csv ;;

	-t|--title) title ;;

	-j|--json) json ;;

	-i|--influx) influx ;;

	-n|--names) names ;;

	-nj|-jn|--names_json) names_json ;;

	-l|--log) log "$2" "$4" ;;

	# for testing
	-a|--all) csv; echo; title; echo;  json; echo; influx; echo; names_json; echo; names ;;

	*) exit 1 ;;
esac


# the format of macs.csv should be:
# MAC address,name
# MAC address,!name
# MAC address,name?
# MAC address,!name?

# any lines without a MAC address won't get used and any fields after the name will be ignored
# additionally, any name with an exclamation mark ("!") will not be shown by names()
# and any name containing a question mark ("?") will not be counted in $COUNT

# NOTE, while having an empty field for the display name column currently hase the same effect as having both "!" and "?", this could be subject to change
