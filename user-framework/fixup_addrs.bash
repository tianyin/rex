#!/bin/bash

# static uint64_t (*bpf_get_current_pid_tgid)(void) = (void *) 
# static void (*bpf_test_call)(void) = (void *) 
# static long (*bpf_trace_printk)(const char *fmt, uint32_t fmt_size, ...) = (void *) 
cat prog-run.c \
    | grep stub \
    | grep -v printf \
    | sort -k 2 \
    | sed s/^/"static "/ \
    | sed s/"("/")("/ \
    | sed s/"stub_"/"(*"/ \
    | sed s/" {"/" = (void *)0"/ \
          > /tmp/1

# 0000000000401360;
# 0000000000401370;
# 0000000000401200;
nm prog-run \
    | grep stub \
    | sort -k 3 \
    | cut -f 1 -d' ' \
    | sed s/$/";"/ \
          > /tmp/2

paste -d'x' /tmp/1 /tmp/2 > interface.h


# pub const STUB_BPF_GET_CURRENT_PID_TGID : u64 = 0
# pub const STUB_BPF_TEST_CALL : u64 = 0
# pub const STUB_BPF_TRACE_PRINTK : u64 = 0
cat prog-run.c \
    | grep stub \
    | grep -v printf \
    | sort -k 2 \
    | cut -f 2 -d ' ' \
    | cut -f 1 -d'(' \
    | tr [:lower:] [:upper:] \
    | sed s/^/"pub const "/ \
    | sed s/$/" : u64 = 0"/ \
          > /tmp/r1

paste -d'x' /tmp/r1 /tmp/2 > rust_test/src/interface.rs
