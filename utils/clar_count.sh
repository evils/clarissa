#!/bin/sh

# get the count of MAC addresses named in the macs.csv ($1) for all the found MAC addresses ($2)
# and output a count of the unique names (minus those with "?") and tally of the remaining addresses
# and provide a list of those names (minus those with "!")
# in a variety of formats (specified by $3)

# the format of macs.csv file ($1) should be:
# MAC address,name
# MAC address,!name
# MAC address,name?
# MAC address,!name?

# literal line example:
# ff:ff:ff:ff:ff:ff,broadcast,this is an example, don't use this

# any lines without a MAC address won't get used and any fields after the name will be ignored
# additionally, any name with an exclamation mark ("!") will not be shown by names()
# and any name containing a question mark ("?") will not be counted in $COUNT

# NOTE, while having an empty field for the display name column currently hase the same effect as having both "!" and "?", this could be subject to change

# the found MAC addresses argument ($2) should point to an output socket of clarissa
# for example: /var/run/192.168.0.0-16

# the format options ($3) are:
# -c or --csv, CSV with header (accepted by telegraf (for influxdb))
# -t or --title, short CSV showing the count of known entities and everything else
# -j or --json, json format (accepted by telegraf (for influxdb))
# -i or --influx, influx line protocol (accepted by telegraf (for influxdb))
# -n or --names, show all names minus those with an exclamation mark "!"
# -nj or --names_json, same as --names but in a json array
# -a or --all

# additionally, there is a --log option
# count --log <salt> <output file>
# this hashes and salts detected MAC addresses
# and enters the result in a log file which is deduplicated
# if no salt provided a random salt is generated at the start of logging
# if no output file is specified $HOME/.local/clarissa/clar_$(date +%s).log is used
# this allows anonymous collecting of the number of unique devices seen during the runtime of this logging function
# and if a salt is supplied, combination of several log files
# to get the number of unique devices seen across logging instances


# maybe set this to measurement's location? (useful for influxdb)
NAME="clarissa"

# show correct usage if used incorrectly
if [ -z "$3" ]; then
echo "Please use the following format:"
echo "count [path to macs.csv] [path to clarissa's output] [option (-a for all)]"
fi


dir="$(cd "$(dirname "$0")" && pwd -P)"
clar=$(command -v ./clarissa || command -v clarissa || command -v "${dir}"/clarissa)

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
done <<< "$(${clar} cat "$@" | grep -v '#')"

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

if [ -z "$3" ]; then
	log=${HOME}/.local/clarissa/clar_"$(date +%s)".log
	mkdir -p "$(dirname "${log}")"
else
	log="$3"
fi


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
