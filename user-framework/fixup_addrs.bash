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
