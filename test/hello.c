
typedef unsigned long __u32;
typedef unsigned long long __u64;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 0x0000000000400850;
    //0xffffffff8114cab0;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 0x0000000000400890;
    //0xffffffff81178a80;

#if 0
#define bpf_printk(s,x...)                       \
    do {                                        \
        bpf_trace_printk(s, strlen(s), x);      \
    } while(0)

static int strlen(char *s) {
    int i = 0;
    while (s[i++] != 0)
        ;
    return i;
}
#endif

int bpf_main(void *ctx) {
    int pid = bpf_get_current_pid_tgid() >> 32;

	bpf_trace_printk("BPF triggered from PID %d.\n", 29, pid);

	return 0;
}
