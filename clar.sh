#!/usr/bin/env sh

dir="$(pwd -P "$(dirname "$0")")"

# shellcheck disable=SC1091
# shellcheck disable=SC1090
case "$1" in
	count|show|scan) call=$1; shift 1; . "${dir}/clar_${call}.sh" ;;
	cat) exec "${dir}/clarissa" "$@" | sort ;;
	*) exec "${dir}/clarissa" "$@" ;;
esac
