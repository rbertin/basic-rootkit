#!/bin/sh
if [ $# -eq 0 ]; then
    echo "Usage: $0 module_name"
    exit 1
fi

rmmod ${1}
insmod ${1}.ko
X=`grep $1 /proc/devices`
if [ "$X" != "" ]; then
    set $X
    rm -f /dev/$2
    mknod /dev/$2 c $1 0
else
    echo "Module $1 not loaded !"
    exit 1
fi

