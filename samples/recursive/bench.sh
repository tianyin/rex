#!/bin/bash

for i in {0..32}; do
	./event-trigger 5000 $i
	cat /sys/kernel/debug/tracing/trace > "./output/rust_${i}"
	# cat /sys/kernel/debug/tracing/trace > "./output/bpf_${i}"
	echo > /sys/kernel/debug/tracing/trace
	echo $i
	sleep 0.5
done
