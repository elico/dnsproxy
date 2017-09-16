#!/usr/bin/env bash
# List of arches
#darwin_386    freebsd_386   freebsd_arm   linux_amd64   netbsd_386    netbsd_arm    openbsd_386   plan9_386     windows_386
#darwin_amd64  freebsd_amd64 linux_386     linux_arm     netbsd_amd64  obj           openbsd_amd64 tool          windows_amd64

mkdir bin >/dev/null 2>&1
export BINARY=dnsproxy-with-drbp_
export GOOS=$1
export GOARCH=$2
export GOARM=$3
export CGO_ENABLED=0
case $GOOS in 
	windows)
		go build -o "./bin/`echo $BINARY``echo $GOOS`_`echo $GOARCH`.exe"
	;;
	linux)
		case $GOARCH in 
			arm)
				go build -o "./bin/`echo $BINARY``echo $GOOS`_`echo $GOARCH$GOARM`"
			;;
			*)
				go build -o "./bin/`echo $BINARY``echo $GOOS`_`echo $GOARCH`"
			;;
		esac

	;;
	*)
		go build -o "./bin/`echo $BINARY``echo $GOOS`_`echo $GOARCH`"
	;;
esac
echo -n "finished building for: "
echo -n $GOOS
echo -n "_"
echo  $GOARCH
