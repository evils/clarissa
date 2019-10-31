#!/usr/bin/env sh

rev="9fb988baa6fbdbf872a3759d25f70a7d1330c399"
path="https://raw.githubusercontent.com/hdm/mac-ages/$rev/data/ieee/"
tables="cid iab mam oui oui36"

file="clar_OUI.csv"
tmp=".tmp_$file"

# to ensure this script ran correctly
# should get checked by nix regardless, but not elsewhere
sha256="94eecdda59ebe6563edb0426fba947330fd590c2c2d8725f04eae1ee99075e9b  -"
tries=2

if [ "$(type wget)" ]; then
	command="wget -qO-"
elif [ "$(type curl)" ]; then
	command="curl -s"
else
	echo "couldn't find a download command"
	exit 1
fi

fault=0
count=0
while [ $count -lt $tries ]; do

	if [ $count -ge $tries ]; then fault=1; break; fi

	rm -f $tmp $file

	for table in $tables; do
		$command "$path$table.csv" | tail -n +2 >> $tmp
	done

	if [ -z "$(head $tmp)" ]; then
		echo "temporary file is empty"
		count=$(( count + 1 ))
		continue
	fi

	output=$(sha256sum < $tmp)
	if [ "$output" != "$sha256" ]; then
		echo "hash mismatch"
		echo "wanted: $sha256"
		echo "got:    $output"
		count=$(( count + 1 ))
		continue
	fi
	break
done

if [ $fault -gt 0 ]; then
	echo "failed to get $file"
	rm -rf $tmp $file
	exit
fi

rm -f $file
{
	echo "# This file is generated by OUI_assemble.sh for clarissa show,"
	echo "# part of the clarissa project (gitlab.com/evils/clarissa)."
	echo "# Currently, due my bad handling of the CSV source,"
	echo "# approximately 10 vendor names are significantly truncated."
	echo "#"
	echo "# This file is based on the IEEE data in https://github.com/hdm/mac-ages"
	echo "# And carries the license attributed by that project:"
	echo "# CC-BY 4.0"
	echo
# shitty CSV handling, affects 10 in 37951 names?
	awk -F ',' '{print $2","$3}' $tmp | sed 's/"//g' | sort
} >> $file

rm -f $tmp
