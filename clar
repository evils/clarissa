#/usr/bin/env sh

case $1 in
	count) shift 1; ./clar_count.sh $@ ;;
	scan) shift 1; ./clar_scan.sh $@ ;;
	*) ./clarissa $@ ;;
esac
