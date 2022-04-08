// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
//#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
// #include <sys/time.h>
// #include <sys/resource.h>
// #include <sys/wait.h>

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <sys/ioctl.h>
#include <asm/unistd.h>
#include <linux/bpf.h>

#include "interface.h"

static int cstate_map_fd, pstate_map_fd;

#define MAX_CPU			8
#define MAX_PSTATE_ENTRIES	5
#define MAX_CSTATE_ENTRIES	3
#define MAX_STARS		40

#define CPUFREQ_MAX_SYSFS_PATH	"/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq"
#define CPUFREQ_LOWEST_FREQ	"208000"
#define CPUFREQ_HIGHEST_FREQ	"12000000"

struct cpu_stat_data {
	unsigned long cstate[MAX_CSTATE_ENTRIES];
	unsigned long pstate[MAX_PSTATE_ENTRIES];
};

static struct cpu_stat_data stat_data[MAX_CPU];

static void cpu_stat_print(void)
{
	int i, j;
	char state_str[sizeof("cstate-9")];
	struct cpu_stat_data *data;

	/* Clear screen */
	printf("\033[2J");

	/* Header */
	printf("\nCPU states statistics:\n");
	printf("%-10s ", "state(ms)");

	for (i = 0; i < MAX_CSTATE_ENTRIES; i++) {
		sprintf(state_str, "cstate-%d", i);
		printf("%-11s ", state_str);
	}

	for (i = 0; i < MAX_PSTATE_ENTRIES; i++) {
		sprintf(state_str, "pstate-%d", i);
		printf("%-11s ", state_str);
	}

	printf("\n");

	for (j = 0; j < MAX_CPU; j++) {
		data = &stat_data[j];

		printf("CPU-%-6d ", j);
		for (i = 0; i < MAX_CSTATE_ENTRIES; i++)
			printf("%-11ld ", data->cstate[i] / 1000000);

		for (i = 0; i < MAX_PSTATE_ENTRIES; i++)
			printf("%-11ld ", data->pstate[i] / 1000000);

		printf("\n");
	}
}

static void cpu_stat_update(int cstate_fd, int pstate_fd)
{
	unsigned long key, value;
	int c, i;

	for (c = 0; c < MAX_CPU; c++) {
		for (i = 0; i < MAX_CSTATE_ENTRIES; i++) {
			key = c * MAX_CSTATE_ENTRIES + i;
			bpf_map_lookup_elem(cstate_fd, &key, &value);
			stat_data[c].cstate[i] = value;
		}

		for (i = 0; i < MAX_PSTATE_ENTRIES; i++) {
			key = c * MAX_PSTATE_ENTRIES + i;
			bpf_map_lookup_elem(pstate_fd, &key, &value);
			stat_data[c].pstate[i] = value;
		}
	}
}

/*
 * This function is copied from 'idlestat' tool function
 * idlestat_wake_all() in idlestate.c.
 *
 * It sets the self running task affinity to cpus one by one so can wake up
 * the specific CPU to handle scheduling; this results in all cpus can be
 * waken up once and produce ftrace event 'trace_cpu_idle'.
 */
static int cpu_stat_inject_cpu_idle_event(void)
{
	int rcpu, i, ret;
	cpu_set_t cpumask;
	cpu_set_t original_cpumask;

	ret = sysconf(_SC_NPROCESSORS_CONF);
	if (ret < 0)
		return -1;

	rcpu = sched_getcpu();
	if (rcpu < 0)
		return -1;

	/* Keep track of the CPUs we will run on */
	sched_getaffinity(0, sizeof(original_cpumask), &original_cpumask);

	for (i = 0; i < ret; i++) {

		/* Pointless to wake up ourself */
		if (i == rcpu)
			continue;

		/* Pointless to wake CPUs we will not run on */
		if (!CPU_ISSET(i, &original_cpumask))
			continue;

		CPU_ZERO(&cpumask);
		CPU_SET(i, &cpumask);

		sched_setaffinity(0, sizeof(cpumask), &cpumask);
	}

	/* Enable all the CPUs of the original mask */
	sched_setaffinity(0, sizeof(original_cpumask), &original_cpumask);
	return 0;
}

/*
 * It's possible to have no any frequency change for long time and cannot
 * get ftrace event 'trace_cpu_frequency' for long period, this introduces
 * big deviation for pstate statistics.
 *
 * To solve this issue, below code forces to set 'scaling_max_freq' to 208MHz
 * for triggering ftrace event 'trace_cpu_frequency' and then recovery back to
 * the maximum frequency value 1.2GHz.
 */
static int cpu_stat_inject_cpu_frequency_event(void)
{
	int len, fd;

	fd = open(CPUFREQ_MAX_SYSFS_PATH, O_WRONLY);
	if (fd < 0) {
		printf("failed to open scaling_max_freq, errno=%d %d\n", errno, __LINE__);
		return fd;
	}

	len = write(fd, CPUFREQ_LOWEST_FREQ, strlen(CPUFREQ_LOWEST_FREQ));
	if (len < 0) {
		printf("failed to open scaling_max_freq, errno=%d %d\n", errno, __LINE__);
		goto err;
	}

	len = write(fd, CPUFREQ_HIGHEST_FREQ, strlen(CPUFREQ_HIGHEST_FREQ));
	if (len < 0) {
		printf("failed to open scaling_max_freq, errno=%d %d\n", errno, __LINE__);
		goto err;
	}

err:
	close(fd);
	return len;
}

static void int_exit(int sig)
{
	cpu_stat_inject_cpu_idle_event();
	cpu_stat_inject_cpu_frequency_event();
	cpu_stat_update(cstate_map_fd, pstate_map_fd);
	cpu_stat_print();
	exit(0);
}

#define ERR(x...)                               \
    do {                                        \
        fprintf(stderr, x);                              \
        return 1;                               \
    } while(0);

#define PERR(x)                                 \
    do {                                        \
        perror(x);                              \
        return 1;                               \
    } while(0);

#define BPF_PROG_LOAD_DJW  0x1234beef
#define MAX_PROG_SZ (8192 * 4)

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int  group_fd, unsigned long flags)
{
    int ret;

    ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
                  group_fd, flags);
    return ret;
}

static int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int do_actual_bpf(int fd, int *used_maps) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    strcpy(attr.prog_name,"cool_prog");
    attr.rustfd = fd;
    attr.kern_version = KERNEL_VERSION(5, 13, 0);
    attr.license = (__u64)"GPL";
    attr.iu_maps = (__u64)used_maps;
    attr.iu_maps_len = 1;
    return bpf(BPF_PROG_LOAD_DJW, &attr, sizeof(attr));
}

int bpf_map_create(int id) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_HASH;
    attr.key_size = 4;
    attr.value_size = 8;
    attr.max_entries = 40;
    attr.is_iu_map = 1;
    attr.iu_idx = id;
    return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

int main(void)
{
	int ret, fd;
	int used_maps[3];
	char temp[13];

	if ((cstate_map_fd = bpf_map_create(0)) < 0) {
        PERR("bpf_map_create");
    }
	if ((pstate_map_fd = bpf_map_create(1)) < 0) {
        PERR("bpf_map_create");
    }
	if ((fd = bpf_map_create(2)) < 0) {
        PERR("bpf_map_create");
    }

	used_maps[0] = cstate_map_fd;
	used_maps[1] = pstate_map_fd;
	used_maps[2] = fd;

	fd = open("./target/debug/cpustat_idle", O_RDONLY);
    if (!fd)
        ERR("Couldn't open first file\n");

	int fd3 = open("./target/debug/cpustat_freq", O_RDONLY);
    if (!fd)
        ERR("Couldn't open second file\n");

    int bpf_fd = do_actual_bpf(fd, used_maps);
    fprintf(stderr, "bpf_fd is %d\n", bpf_fd);
    if (bpf_fd <= 0) {
        PERR("Couldn't load BPF");
    }

    int fd2 = openat(AT_FDCWD, "/sys/kernel/debug/tracing/events/power/cpu_idle/id", O_RDONLY);
    if (fd2 < 0) {
        perror("openat");
        exit(1);
    }
    char config_str[256];
    read(fd2, config_str, 256);
    close(fd2);

    struct perf_event_attr p_attr;
    memset(&p_attr, 0, sizeof(p_attr));
    p_attr.type = PERF_TYPE_TRACEPOINT;
    p_attr.size = PERF_ATTR_SIZE_VER5;
    p_attr.config = atoi(config_str);
    fd2 = perf_event_open(&p_attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd2 < 0) {
        perror("perf_event_open");
        exit(1);
    }
    fprintf(stderr, "perf event opened with %d\n", fd2);
    ioctl(fd2, PERF_EVENT_IOC_SET_BPF, bpf_fd);
    fprintf(stderr, "bpf should be attached now...\n");
    ioctl(fd2, PERF_EVENT_IOC_ENABLE, 0);

    bpf_fd = do_actual_bpf(fd3, used_maps);
    fprintf(stderr, "bpf_fd is %d\n", bpf_fd);
    if (bpf_fd <= 0) {
        PERR("Couldn't load BPF");
    }

    fd2 = openat(AT_FDCWD, "/sys/kernel/debug/tracing/events/power/cpu_frequency/id", O_RDONLY);
    if (fd2 < 0) {
        perror("openat");
        exit(1);
    }
    char config_str2[256];
    read(fd2, config_str2, 256);
    close(fd2);

    struct perf_event_attr p_attr2;
    memset(&p_attr2, 0, sizeof(p_attr2));
    p_attr2.type = PERF_TYPE_TRACEPOINT;
    p_attr2.size = PERF_ATTR_SIZE_VER5;
    p_attr2.config = atoi(config_str2);
    fd2 = perf_event_open(&p_attr2, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd2 < 0) {
        perror("perf_event_open");
        exit(1);
    }
    fprintf(stderr, "perf event opened with %d\n", fd2);
    ioctl(fd2, PERF_EVENT_IOC_SET_BPF, bpf_fd);
    fprintf(stderr, "bpf should be attached now...\n");
    ioctl(fd2, PERF_EVENT_IOC_ENABLE, 0);

	ret = cpu_stat_inject_cpu_idle_event();
	if (ret < 0)
		return 1;

	ret = cpu_stat_inject_cpu_frequency_event();
	if (ret < 0)
		return 1;

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	while (1) {
		cpu_stat_update(cstate_map_fd, pstate_map_fd);
		cpu_stat_print();
		sleep(5);
	}

	return 0;
}