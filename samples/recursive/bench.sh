#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <bpf|rex>"
	exit 1
fi

echo 8192 > /sys/kernel/debug/tracing/buffer_size_kb
mkdir output

if [[ "$1" == "rex" ]]; then
	for i in {0..32}; do
		./event-trigger 5000 $i
		cat /sys/kernel/debug/tracing/trace | tail -5000 >"./output/rust_${i}"
		echo >/sys/kernel/debug/tracing/trace
		echo $i
		sleep 0.5
	done
elif [[ "$1" == "bpf" ]]; then
	for i in {0..32}; do
		./event-trigger 6000 $i
		cat /sys/kernel/debug/tracing/trace | tail -5000  >"./output/bpf_${i}"
		echo >/sys/kernel/debug/tracing/trace
		echo $i
		sleep 0.5
	done
fi

# unlink
rm -rf /sys/fs/bpf/*
