#!/usr/bin/env bash

if [ "$#" -ne 2 ]; then
	echo "Usage: $0 <rex|bpf> <atomic|hash|array>"
	exit 1
fi

mkdir output
echo 8192 > /sys/kernel/debug/tracing/buffer_size_kb

if [[ "$1" == "rex" ]]; then
	./event-trigger 6000 1
	cat /sys/kernel/debug/tracing/trace | tail -5000 >"./output/rex_${2}.txt"
elif [[ "$1" == "bpf" ]]; then
	./event-trigger 6000 1
	cat /sys/kernel/debug/tracing/trace | tail -5000 >"./output/bpf_${2}.txt"
fi


# clean buffer
echo >/sys/kernel/debug/tracing/trace

# unlink
rm -rf /sys/fs/bpf/*
