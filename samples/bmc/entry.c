#include <bpf.h>
#include <libbpf.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "libiu.h"

#define BPF_SYSFS_ROOT "/sys/fs/bpf"

#define STATS_PATH "/tmp/bmc_stats.txt"
#define STATS_INTERVAL_PATH "/tmp/bmc_stats_interval.txt"

#define EXE "./target/x86_64-unknown-linux-gnu/release/bmc"

static int nr_cpus = 0;

struct bpf_progs_desc {
	char name[256];
	enum bpf_prog_type type;
	unsigned char pin;
	int map_prog_idx;
	struct bpf_program *prog;
};

static struct bpf_progs_desc progs[] = {
	{ "xdp_rx_filter", BPF_PROG_TYPE_XDP, 0, -1, NULL },
	// {"bmc_hash_keys", BPF_PROG_TYPE_XDP, 0, BMC_PROG_XDP_HASH_KEYS, NULL},
	// {"bmc_prepare_packet", BPF_PROG_TYPE_XDP, 0,
	// BMC_PROG_XDP_PREPARE_PACKET, NULL},
	// {"bmc_write_reply", BPF_PROG_TYPE_XDP, 0, BMC_PROG_XDP_WRITE_REPLY,
	// NULL},
	// {"bmc_invalidate_cache", BPF_PROG_TYPE_XDP, 0,
	// BMC_PROG_XDP_INVALIDATE_CACHE, NULL},

	{ "xdp_tx_filter", BPF_PROG_TYPE_SCHED_CLS, 1, -1, NULL },
	// {"bmc_update_cache", BPF_PROG_TYPE_SCHED_CLS, 0,
	// BMC_PROG_TC_UPDATE_CACHE, NULL},
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG || level == LIBBPF_INFO) {
		return vfprintf(stderr, format, args);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
	int base_fd, rx_prog_fd, tx_prog_fd, xdp_main_prog_fd;
	struct bpf_object_load_attr load_attr;
	struct bpf_program *rx_prog, *tx_prog;
	struct bpf_object *obj;
	char filename[PATH_MAX];
	int err, prog_count;
	__u32 xdp_flags = 0;
	int *interfaces_idx;
	int ret = 0;

	int opt;
	int interface_count = 0;
	int sig, quit = 0;

	libbpf_set_print(libbpf_print_fn);
	iu_set_debug(1); // enable debug info

	interface_count = argc - optind;
	if (interface_count <= 0) {
		fprintf(stderr,
			"Missing at least one required interface index\n");
		exit(EXIT_FAILURE);
	}

	interfaces_idx = calloc(sizeof(int), interface_count);
	if (interfaces_idx == NULL) {
		fprintf(stderr, "Error: failed to allocate memory\n");
		return 1;
	}

	for (int i = 0; i < interface_count && optind < argc; optind++, i++) {
		interfaces_idx[i] = atoi(argv[optind]);
	}
	nr_cpus = libbpf_num_possible_cpus();

	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	sigaddset(&signal_mask, SIGUSR1);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit failed");
		return 1;
	}

	obj = iu_object__open(EXE);
	if (!obj) {
		fprintf(stderr, "Object could not be opened\n");
		exit(1);
	}

	rx_prog = bpf_object__find_program_by_name(obj, "xdp_rx_filter");
	if (!rx_prog) {
		fprintf(stderr, "start not found\n");
		exit(1);
	}

	xdp_main_prog_fd = bpf_program__fd(rx_prog);
	if (xdp_main_prog_fd < 0) {
		fprintf(stderr, "Error: bpf_program__fd failed\n");
		return 1;
	}

	xdp_flags |= XDP_FLAGS_DRV_MODE;
	/* xdp_flags |= XDP_FLAGS_SKB_MODE; */
	for (int i = 0; i < interface_count; i++) {
		if (bpf_set_link_xdp_fd(interfaces_idx[i], xdp_main_prog_fd,
					xdp_flags) < 0) {
			fprintf(stderr,
				"Error: bpf_set_link_xdp_fd failed for interface %d\n",
				interfaces_idx[i]);
			return 1;
		} else {
			printf("Main BPF program attached to XDP on interface %d\n",
			       interfaces_idx[i]);
		}
	}

	char prog_name[256] = "xdp_tx_filter";
	tx_prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!tx_prog) {
		fprintf(stderr, "tx_prog not found\n");
		exit(1);
	}
	printf("tx_prog: %s\n", bpf_program__name(tx_prog));

	int len = snprintf(filename, PATH_MAX, "%s/%s", BPF_SYSFS_ROOT,
			   prog_name);
	if (len < 0) {
		fprintf(stderr, "Error: Program name '%s' is invalid\n",
			"xdp_tx_filter");
		return -1;
	} else if (len >= PATH_MAX) {
		fprintf(stderr, "Error: Program name '%s' is too long\n",
			prog_name);
		return -1;
	}

	ret = bpf_program__pin(tx_prog, filename);
	if (ret != 0) {
		fprintf(stderr,
			"Error: Failed to pin program '%s' to path %s with error code %d\n",
			prog_name, filename, ret);
		return ret;
	}

	err = sigprocmask(SIG_BLOCK, &signal_mask, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: Failed to set signal mask\n");
		exit(EXIT_FAILURE);
	}

	while (!quit) {
		err = sigwait(&signal_mask, &sig);
		if (err != 0) {
			fprintf(stderr, "Error: Failed to wait for signal\n");
			exit(EXIT_FAILURE);
		}

		switch (sig) {
		case SIGINT:
		case SIGTERM:
		case SIGUSR1:
			quit = 1;
			break;

		default:
			fprintf(stderr, "Unknown signal\n");
			break;
		}
	}

	// if (bpf_program__pin_instance(tx_prog, filename, 0)) {
	//     fprintf(stderr, "Error: Failed to pin program '%s' to path %s\n",
	//             "xdp_tx_filter", filename);
	//     if (errno == EEXIST) {
	//       fprintf(stdout,
	//               "BPF program '%s' already pinned, unpinning it to reload
	//               it\n", "xdp_tx_filter");
	//       if (bpf_program__unpin_instance(tx_prog, filename, 0)) {
	//         fprintf(stderr, "Error: Fail to unpin program '%s' at %s\n",
	//                 "xdp_tx_filter", filename);
	//         return -1;
	//       }
	//     }
	//     return -1;
	// }

	for (int i = 0; i < interface_count; i++) {
		bpf_set_link_xdp_fd(interfaces_idx[i], -1, xdp_flags);
	}
	return ret;
}
