typedef unsigned long __u32;
typedef unsigned long uint32_t;
typedef unsigned long long __u64;
typedef unsigned long long uint64_t;
#include "../interface-kernel.h"

int bpf_main(void *ctx) {
    //bpf_test_call();

    int pid = bpf_get_current_pid_tgid() >> 32;
    int tgid = bpf_get_current_pid_tgid() & 0xffffffff;
    bpf_trace_printk("BPF triggered from PID 0x%x 0x%x 0x%x.\n", 35, pid, tgid, 42);
      
    return 0;
}
