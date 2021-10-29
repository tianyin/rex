typedef unsigned long __u32;
typedef unsigned long uint32_t;
typedef unsigned long long __u64;
typedef unsigned long long uint64_t;
#include "../interface.h"

int bpf_main(void *ctx) {
      bpf_test_call();

      int pid = bpf_get_current_pid_tgid() >> 32;
      bpf_trace_printk("BPF triggered from PID 0x%x.\n", 29, pid);
      
      return 0;
}
