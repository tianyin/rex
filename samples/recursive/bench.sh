#!/usr/bin/env bash

if [ "$#" -ne 1 ]; then
	echo "Usage: $0 <bpf|rex>"
	exit 1
fi

mkdir output

if [[ "$1" == "rex" ]]; then
	for i in {0..32}; do
		./event-trigger 5000 $i
		cat /sys/kernel/debug/tracing/trace >"./output/rust_${i}"
		echo >/sys/kernel/debug/tracing/trace
		echo $i
		sleep 0.5
	done
elif [[ "$1" == "bpf" ]]; then
	for i in {0..32}; do
		./event-trigger 5000 $i
		cat /sys/kernel/debug/tracing/trace >"./output/bpf_${i}"
		echo >/sys/kernel/debug/tracing/trace
		echo $i
		sleep 0.5
	done
fi
