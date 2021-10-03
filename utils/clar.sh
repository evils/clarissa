#!/usr/bin/env bash

# due to the difficulty in calling a shell script that is split up
# this file contains all the shell implementations of the clar subcommands
# and the clar command itself at the end of this file

dir="$(cd "$(dirname "$0")" && pwd -P)"
clar=$(command -v ./clarissa || command -v clarissa || command -v "${dir}"/clarissa)


if [ -f "$CLAR_OUI" ]; then
	oui="$CLAR_OUI"
elif [ -f "$PWD"/clar_OUI.csv ]; then
	oui="$PWD"/clar_OUI.csv
elif [ -f /usr/share/misc/clar_OUI.csv ]; then
	oui=/usr/share/misc/clar_OUI.csv
elif [ -f "$dir"/../share/misc/clar_OUI.csv ]; then
	oui=$(realpath "$dir"/../share/misc/clar_OUI.csv)
elif [ -f "$HOME"/.local/share/clar/clar_OUI.csv ]; then
	oui="$HOME"/.local/share/clar/clar_OUI.csv
elif [ -f "$dir"/clar_OUI.csv ]; then
	oui="$dir"/clar_OUI.csv
elif [ -f "$dir"/../clar_OUI.csv ]; then
	oui=$(realpath "$dir"/../clar_OUI.csv)
fi


clar_show() {

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
		domain="$(timeout "0.1" dig -x "$ipv4" | grep "ANSWER SECTION" -A 1 \
			| awk '{print substr($5, 1, length($5)-1)}' \
			| sed '/^\s*$/d')"
		if [ -z "$domain" ]; then
			domain="$(timeout "0.1" dig -x "$ipv6" | grep "ANSWER SECTION" -A 1 \
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
				vendor="$(if [ -f "$oui" ]
						then printf "(vendor_not_listed_(UAA))"
						else printf "(missing_OUI_file)"
					fi)"
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

}



clar_scan() {

	tmp=".clar_scan_temp_file_delete_this.tmp"

	c_cat() {
		"${clar}" cat "$@" | grep -v "#"
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

	c_cat "$@" | sort | grep -sv "0.0.0.0" | tee "$tmp" \
	| while read -r "REPLY"; do
		ipv4="$(echo "$REPLY" | awk '{print $3}')"
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
	printf "\\nEnding, %s responded, consider using \"clar show\"" "$count"
	clar=$(c_cat "$@" | wc -l | awk '{print $1}')
	diff=$(( clar - count ))
	if [ "$diff" -gt 0 ]; then
		printf ", it has %s more result" "$diff"
		if [ "$diff" -ne 1 ]; then
			printf "s"
		fi
	fi

	echo

	rm -f "$tmp"

}



clar_sort() {

	result="$("${clar}" cat "$@")"

	echo "${result}" | grep "#"
	echo "${result}" | grep -v "#" | sort

}



clar_count() {

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
	# if no output file is specified $HOME/.local/share/clar/$(date +%s).log is used
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
		log=${HOME}/.local/share/clar/"$(date +%s)".log
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

}




# actual clar command

case "$1" in
	count|show|scan|sort) call=$1; shift 1;  "clar_${call}" ;;
	help)
		echo "clarissa utility"
		echo "exposes several sub-commands"
		printf "\tcount\n"
			printf "\t\toutput a count of known and unknown detected devices is a variety of formats\n"
			printf "\t\tman 1 clar-count\n"
		printf "\tshow\n"
			printf "\t\tshow detected MAC addresses with vendor ID, IPv4 address, domain name and IPv6 address\n"
			printf "\t\tman 1 clar-show\n"
		printf "\tscan\n"
			printf "\t\tarp-scan compatible output\n"
			printf "\t\tman 1 clar-scan\n"
		printf "\tsort\n"
			printf "\t\tsame output as clarissa cat, but with results sorted by MAC address\n"
			printf "\t\tman 1 clar-sort\n"
		printf "\thelp\n"
			printf "\t\tshow this exposition\n"
			printf "\t\tman 1 clar\n\n"
		echo "all other arguments get passed to clarissa"
	;;
	*) exec "${clar}" "$@" ;;
esac
