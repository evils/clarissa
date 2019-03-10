#!/usr/bin/env bash
# counts the number of members and the number of unknown and infrastructure devices detected by clarissa
# currently expects a file in the execution path containing
# MAC address,alias

# intended to be used for telegraf, which interprets all numbers as floats by default
# somehow the csv output gets interpreted as integers
# to force integer type, add the letter i after the integer e.g.: 7i

# measurement name
NAME="clarissa"

ALIASES=$(./clar_show.sh)

USAGE="-c, -j, -i or -a; (f)or --csv, --json, --influx formatting or --all. "

if [ -z "$ALIASES" ]; then
	(>&2 echo "No source data found")
	exit 1
fi

if [ -z "$1" ]; then
	(>&2 echo "No output format specified,"; echo "$USAGE")
	exit 1
fi

if [ -n "$2" ]; then
	(>&2 echo "Multiple options not supported, try --all?"; echo "$USAGE")
	exit 1
fi


# count members, infrastructure devices and unknown devices
MEMBERS=$(echo "$ALIASES" | sort | uniq | grep -Evc '\(.*\)|([a-f0-9]{2}:){5}[a-f0-9]{2}$')
INFRA=$(echo "$ALIASES" | grep -Ec '\(.*\)|\).*\(')
UNKNOWN=$(($(echo "$ALIASES" | grep -Evc '\(.*\)|\).*\(') - $MEMBERS))

# ISSUE, indenting the functions adds spaces to output?
# ISSUE, can't indent functions, the tabs 

# formatted counts as:

csv() {
	echo "name,members,unknown,infra"
	echo "$NAME","$MEMBERS","$UNKNOWN","$INFRA"
}

csv_raw() {
	echo "$MEMBERS","$UNKNOWN","$INFRA"
}

title() {
	echo "$MEMBERS","$UNKNOWN"
}

json() {
echo "{\"name\":\"""$NAME""\", \"members\":"$MEMBERS"\
, \"unknown\":"$UNKNOWN", \"infra\":"$INFRA"}"
}

influx() {
echo $NAME" members="$MEMBERS",unknown="$UNKNOWN",infra="$INFRA
}


case "$1" in

	-c|--csv) csv ;;

	-r|--csv_raw) csv_raw ;;

	-t|--title) title ;;

	-j|--json) json ;;

	-i|--influx) influx ;;

	# for testing
	# ISSUE, some newlines aren't working?
	-a|--all) csv; printf "\n"; csv_raw printf "\n"; title printf "\n";  json; printf "\n"; influx ;;

	*) exit 1 ;;
esac
