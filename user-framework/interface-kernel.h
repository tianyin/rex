static uint64_t (*bpf_get_current_pid_tgid)(void) = (void *)0x0000000000401360;
static void (*bpf_test_call)(void) = (void *)0x0000000000401370;
static long (*bpf_trace_printk)(const char *fmt, uint32_t fmt_size, ...) = (void *)0x0000000000401200;
