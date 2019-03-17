#!/usr/bin/env bash

# get the named MAC addresses' names from the macs.csv ($1) for all the found MAC addresses ($2)
# and output a count of the unique names and tally of the remaining addresses
# in a variety of formats (specified by $3)

# maybe set this to measurement's location?
NAME="clarissa"


# do the actual counting

NAMES=()
TALLY=0

while read -r; do
	LINE=$(grep "$REPLY" $1)
	if [ "$LINE" ]; then
		NAMES+=('$(echo $LINE | awk -F "," '{print $2}')' )
	else
		let "TALLY++"
	fi
done < $2

COUNT=$(echo $NAMES | sort | uniq | grep -c -)


# formatted counts as:

csv() {
        echo "name,named,balance"
	echo $NAME","$COUNT","$TALLY
}

title() {
	echo $COUNT","$TALLY
}

json() {
echo "{\"name\":\""$NAME"\", \"named\":"$COUNT", \"balance\":"$TALLY"}"
}

influx() {
echo $NAME" named="$COUNT",balance="$TALLY
}


# handle the options

case "$3" in

        -c|--csv) csv ;;

        -t|--title) title ;;

        -j|--json) json ;;

        -i|--influx) influx ;;

        # for testing
        # ISSUE, some newlines aren't working?
        -a|--all) csv; printf "\n"; title printf "\n";  json; printf "\n"; influx ;;

        *) exit 1 ;;
esac

