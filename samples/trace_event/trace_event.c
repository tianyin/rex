#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/perf_event.h>
#include <linux/unistd.h>

#include "libiu.h"

#define EXE "./target/debug/" SAMPLE_NAME

#define SAMPLE_FREQ 3

static int pid;
static int prog_fd;

static inline long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
							int cpu, int  group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static void read_trace_pipe(void) {
	int trace_pipe_fd;

	trace_pipe_fd = openat(AT_FDCWD, "/sys/kernel/debug/tracing/trace_pipe",
		O_RDONLY);

	for (;;) {
		char c;
		if (read(trace_pipe_fd, &c, 1) == 1)
			putchar(c);
	}
}

static void test_bpf_perf_event(void) {
	int pmu_fd;

	// TODO: For now, only one out of the six events.
	struct perf_event_attr attr_type_sw = {
		.sample_freq = SAMPLE_FREQ,
		.freq = 1,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};

	struct perf_event_attr *attr = &attr_type_sw;

	// TODO: For now, only _all_cpu tests (without _task tests)
	// TODO: For now, only the first CPU
	pmu_fd = perf_event_open(attr, -1, 0 /* cpu_idx */, -1, 0);

	ioctl(pmu_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);

	system("dd if=/dev/zero of=/dev/null count=5000k status=none");
}

int main(void)
{
	int base_fd;

	iu_set_debug(1); // enable debug info

	base_fd = iu_prog_load(EXE);

	if (base_fd < 0)
		exit(1);

	prog_fd = iu_prog_get_subprog(base_fd, "iu_prog1");

	if (prog_fd < 0) {
		fprintf(stderr, "iu_prog1 not found\n");
		exit(1);
	}

	pid = fork();
	if (pid == 0) {
		read_trace_pipe();
		return 0;
	} else if (pid == -1) {
		printf("couldn't spawn process\n");
		return -1;
	}

	test_bpf_perf_event();

	return 0;
}
