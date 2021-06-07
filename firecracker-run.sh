#!/bin/bash -e
rm -f /tmp/firecracker.socket

(sleep 2 && bash firecracker-setup.sh $1 $2 $3)&

./firecracker-bin --api-sock /tmp/firecracker.socket
