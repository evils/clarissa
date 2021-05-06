#!/bin/sh

dir="$(cd "$(dirname "$0")" && pwd -P)"
clar=$(command -v ./clarissa || command -v clarissa || command -v "${dir}"/clarissa)

# shellcheck disable=SC1091
# shellcheck disable=SC1090
case "$1" in
	count|show|scan|sort) call=$1; shift 1; . "${dir}/clar_${call}.sh" ;;
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
