#/usr/bin/env sh

case $1 in
	count) shift 1; exec ./clar_count.sh $@ ;;
	scan) shift 1; exec ./clar_scan.sh $@ ;;
	*) exec ./clarissa $@ ;;
esac
