#!/usr/bin/env sh

dir="$(cd "$(dirname "$0")" && pwd -P)"

# shellcheck disable=SC1091
# shellcheck disable=SC1090
case "$1" in
	count|show|scan) call=$1; shift 1; . "${dir}/clar_${call}.sh" ;;
	cat) exec "${dir}/clarissa" "$@" | sort ;;
	*) exec "${dir}/clarissa" "$@" ;;
esac
