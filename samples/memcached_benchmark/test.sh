#!/bin/bash


memcached -U 11211 -t 4 -m 4096 &
sleep 1
cargo run -r -- -n 100000 -s 127.0.0.1 -p 11211 -t 8 -d
pkill memcached
sleep 1
