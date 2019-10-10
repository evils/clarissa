#!/usr/bin/env sh

rev="9fb988baa6fbdbf872a3759d25f70a7d1330c399"
url="https://raw.githubusercontent.com/hdm/mac-ages/$rev/data/ieee/"
tables=(cid iab mam oui oui36)

file="clar_OUI.csv"
tmp=".tmp_$file"

# to ensure this script ran correctly
# should get checked by nix regardless, but not elsewhere
sha256="645905cc47a4615da7fc66435b1bdf8d0ee9b398cd7820f6983b49259bff89d7  $file"

if [ "$(type wget)" ]; then
	command="wget -qO-"
elif [ "$(type curl)" ]; then
	command="curl -s"
else
	echo "couldn't find a download command"
	exit 1
fi

for table in ${tables[@]}; do
	$command "$url$table.csv" | tail -n +2 >> $tmp
done

if [ -z "$(head $tmp)" ]; then
	echo "temporary file is empty"
	exit 1
else
	rm -f $file
	{
		echo "# This file is generated by OUI_assemble.sh for clarissa scan,"
		echo "# part of the clarissa project (gitlab.com/evils/clarissa)."
		echo "#"
		echo "# This file is based on the IEEE data in https://github.com/hdm/mac-ages"
		echo "# And carries the license attributed by that project:"
		echo "# CC-BY 4.0"
		echo
# shitty CSV handling, affects 10 in 37951 names?
		awk -F ',' '{print $2","$3}' $tmp | sed 's/"//g' | sort
	} >> $file

	output="$(sha256sum $file)"
	if [ "$output" != "$sha256" ]; then
		echo "hash mismatch"
		echo "wanted: $sha256"
		echo "got:    $output"
		rm -f $tmp $file
		exit 1
	fi
	rm -f $tmp
fi
