## helper functions

If I'm not sure about the decision, the function (or group of functions) will follow a question mark.

Next step:
- bpf_map_pop_elem
- bpf_map_peek_elem
- bpf_for_each_map_elem
- bpf_spin_lock
- bpf_spin_unlock
- cgroup helper function
	- bpf_sysctl_get_name
	- bpf_sysctl_get_current_value
	- bpf_sysctl_get_new_value
	- bpf_sysctl_set_new_value
- bpf_strtol bpf_strtoul (we could use something like u64::from_str_radix)
- bpf_snprintf


Function wrapper:
- bpf_map_lookup_elem
- bpf_map_update_elem
- bpf_map_delete_elem
- bpf_map_push_elem
- bpf_probe_read
- bpf_probe_read_kernel

Half implemented in Rust:
- bpf_ktime_get_coarse_ns
- bpf_get_prandom_u32
- perf_event
	- bpf_get_stackid_pe -> bpf_get_stackid ?

All implemented in Rust:
- bpf_strcmp
- bpf_strncmp
- bpf_get_numa_node_id
- bpf_jiffies64
- bpf_ktime_get_ns
- bpf_ktime_get_boot_ns
- bpf_get_smp_processor_id
- bpf_trace_printk
- bpf_per_cpu_ptr ?
- bpf_this_cpu_ptr ?
- task_struct
	- bpf_get_current_pid_tgid
	- bpf_get_current_uid_gid
	- bpf_get_current_comm
	- bpf_get_current_task
	- bpf_override_return
	- bpf_task_pt_regs
- perf_event
	- bpf_perf_prog_read_value


Not implemented yet
- bpf_tail_call ?
- bpf_perf_event_output
- bpf_probe_write_user
- bpf_probe_read_str
	- bpf_probe_read_user_str
	- bpf_probe_read_kernel_str
- bpf_perf_event_read_value
- bpf_perf_event_read
- bpf_get_stack
- bpf_get_local_storage
- bpf_inode_storage_get
- bpf_inode_storage_delete
- bpf_task_storage_get
- bpf_task_storage_delete
- bpf_send_signal
- bpf_send_signal_thread
- bpf_read_branch_records
- bpf_get_ns_current_pid_tgid
- bpf_ringbuf_output
	- https://docs.kernel.org/bpf/ringbuf.html
- bpf_ringbuf_reserve
- bpf_ringbuf_submit
- bpf_ringbuf_discard
- bpf_ringbuf_query
- bpf_get_task_stack
- bpf_copy_from_user

- bpf_seq_printf_btf
- bpf_ima_inode_hash
- bpf_sys_bpf
- bpf_btf_find_by_name_kind
- bpf_sys_close
- bpf_timer_init
- bpf_timer_set_callback
- bpf_timer_start
- bpf_timer_cancel
- bpf_get_func_ip
- bpf_probe_read_user
- bpf_seq_printf
- bpf_seq_write
- bpf_snprintf_btf
	- https://www.kernel.org/doc/html/next/bpf/btf.html

Discarded:
- network
- sock?
- cgroup?
- bpf_d_path 
- bpf_get_current_task_btf
- bpf_loop

