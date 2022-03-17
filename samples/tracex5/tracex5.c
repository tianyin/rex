#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>

#define BPF_PROG_LOAD_DJW 0x1234beef

/* install fake seccomp program to enable seccomp code path inside the kernel,
 * so that our kprobe attached to seccomp_phase1() can be triggered
 */
static void install_accept_all_seccomp(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};
	if (prctl(PR_SET_SECCOMP, 2, &prog))
		perror("prctl");
}

static int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

int do_actual_bpf(int fd) {
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_KPROBE;
	strcpy(attr.prog_name,"cool_prog");
	attr.rustfd = fd;
	attr.kern_version = KERNEL_VERSION(5, 13, 0);
	attr.license = (__u64)"GPL";
	return bpf(BPF_PROG_LOAD_DJW, &attr, sizeof(attr));
}

#define STRERR_BUFSIZE  128

/*
 * this function is expected to parse integer in the range of [0, 2^31-1] from
 * given file using scanf format string fmt. If actual parsed value is
 * negative, the result might be indistinguishable from error
 */
static int parse_uint_from_file(const char *file, const char *fmt)
{
	int err, ret;
	FILE *f;

	f = fopen(file, "r");
	if (!f) {
		err = -errno;
		perror("fopen");
		return err;
	}
	err = fscanf(f, fmt, &ret);
	if (err != 1) {
		err = err == EOF ? -EIO : -errno;
		perror("fscanf");
		fclose(f);
		return err;
	}
	fclose(f);
	return ret;
}

static int determine_kprobe_perf_type(void)
{
	const char *file = "/sys/bus/event_source/devices/kprobe/type";

	return parse_uint_from_file(file, "%d\n");
}

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

#define PERF_UPROBE_REF_CTR_OFFSET_BITS 32
#define PERF_UPROBE_REF_CTR_OFFSET_SHIFT 32

static int perf_event_open_probe(const char *name, uint64_t offset, int pid,
				size_t ref_ctr_off)
{
	struct perf_event_attr attr = {};
	int type, pfd, err;

	if (ref_ctr_off >= (1ULL << PERF_UPROBE_REF_CTR_OFFSET_BITS))
		return -EINVAL;

	type = determine_kprobe_perf_type();
	if (type < 0) {
		perror("determine_kprobe_perf_type");
		return type;
	}

	attr.size = sizeof(attr);
	attr.type = type;
	attr.config |= (__u64)ref_ctr_off << PERF_UPROBE_REF_CTR_OFFSET_SHIFT;
	attr.config1 = ptr_to_u64(name); /* kprobe_func or uprobe_path */
	attr.config2 = offset;		 /* kprobe_addr or probe_offset */

	/* pid filter is meaningful only for uprobes */
	pfd = syscall(__NR_perf_event_open, &attr,
		      pid < 0 ? -1 : pid /* pid */,
		      pid == -1 ? 0 : -1 /* cpu */,
		      -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
	if (pfd < 0) {
		err = -errno;
		perror("perf_event_open");
		return err;
	}
	return pfd;
}

static int kprobe_attach(int progfd, char *func)
{
	int pfd = perf_event_open_probe(func, 0, -1, 0);
	if (pfd < 0) {
		perror("perf_event_open_probe");
		return -1;
	}
	int ret = ioctl(pfd, PERF_EVENT_IOC_SET_BPF, progfd);
	if (ret < 0) {
		perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
		return -1;
	}
	ret = ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
	if (ret < 0) {
		perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
		return -1;
	}
	return 0;
}

#define DEBUGFS "/sys/kernel/debug/tracing/"

static void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int main(void)
{
	int fd1, fd2;
	FILE *f;

	fd1 = open("./target/debug/tracex5", O_RDONLY);
	if (fd1 < 0) {
		perror("open");
		goto out_err;
	}

	fd2 = do_actual_bpf(fd1);

	if (fd2 < 0) {
		perror("bpf");
		goto out_err;
	}

	if (close(fd1) < 0) {
		perror("close");
		goto out_err;
	}

	if (kprobe_attach(fd2, "__seccomp_filter") < 0) {
		perror("kprobe_attach");
		goto out_err;
	}

	install_accept_all_seccomp();

	f = popen("dd if=/dev/zero of=/dev/null count=5", "r");
	(void) f;

	read_trace_pipe();

	return EXIT_SUCCESS;

out_err:
	return EXIT_FAILURE;
}
