#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/perf_event.h>
#include <linux/unistd.h>

#include "libiu.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define EXE "./target/x86_64-unknown-linux-gnu/release/recursive"

int main(void)
{
	int trace_pipe_fd;
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;

	iu_set_debug(1); // enable debug info

	obj = iu_object__open(EXE);
	if (!obj) {
		fprintf(stderr, "Object could not be opened\n");
		exit(1);
	}

	prog = bpf_object__find_program_by_name(obj, "iu_recursive");
	if (!prog) {
 		fprintf(stderr, "_start not found\n");
 		exit(1);
 	}

	// Populate map with starting conditions
	int data_map_fd = bpf_object__find_map_fd_by_name(obj, "data_map");
	int pid_key = 0;
	int n_key = 1;
	int pid = getpid();
	printf("PID: %d\n", pid);
	int n_init = 10;
	bpf_map_update_elem(data_map_fd, &pid_key, &pid, BPF_ANY);
	bpf_map_update_elem(data_map_fd, &n_key, &n_init, BPF_ANY);

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		return 0;
	}
	bpf_link__pin(link, "/sys/fs/bpf/recursive_link");

	// trace_pipe_fd = openat(AT_FDCWD, "/sys/kernel/debug/tracing/trace_pipe",
	// 	O_RDONLY);

	// for (;;) {
    //     char c;
    //     if (read(trace_pipe_fd, &c, 1) == 1)
    //         putchar(c);
    // }

	fprintf(stderr, "Triggered a write syscall\n");

	return 0;
}
