all: cpustat rustcpustat

cpustat: cpustat.c
	clang -I $(HOME)/linux/usr/include -g $< -o $@

rustcpustat: src/*
	cargo rustc --bin cpustat_idle -vv -- -C link-arg=-nostartfiles -A unused
	cargo rustc --bin cpustat_freq -vv -- -C link-arg=-nostartfiles -A unused
	