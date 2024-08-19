#!/bin/bash

MOUNT_PATH="/media/$USER/RPI-RP2"
RUN_PATH="/dev/ttyACM0"

if [ ! -d $MOUNT_PATH ] 
then 
		echo "sending reset signal"
		sudo stty -F $RUN_PATH 1200
		echo "waiting to detect pico"
		while [ ! -d $MOUNT_PATH ] 
		do 
			sleep 0.1 
		done
fi

echo "pico found on $MOUNT_PATH!"
sleep 1
if [ "$*" = "" ]; then echo "rebooting pico"; sudo picotool reboot; exit; fi
echo "copying file $1"
sudo cp $1 $MOUNT_PATH
sleep 2
echo "done copying, starting minicom"
minicom -D $RUN_PATH
