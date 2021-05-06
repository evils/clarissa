#!/bin/sh

dir="$(cd "$(dirname "$0")" && pwd -P)"
clar=$(command -v ./clarissa || command -v clarissa || command -v "${dir}"/clarissa)

result="$("${clar}" cat $@)"

echo "${result}" | grep "#"
echo "${result}" | grep -v "#" | sort
