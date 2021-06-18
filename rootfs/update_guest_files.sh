#!/bin/bash

mnt=$(mktemp -d)
sudo mount $1 $mnt

sudo mkdir -p $mnt/guest
sudo cp rootfs/guest/* $mnt/guest/

sudo umount $mnt
rmdir $mnt
