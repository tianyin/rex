#include <assert.h>
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

#include <librex.h>

#define BPF_SYSFS_ROOT "/sys/fs/bpf"

#define EXE "./target/x86_64-unknown-none/release/xdp_test"

static int nr_cpus = 0;

struct bpf_progs_desc {
	char name[256];
	enum bpf_prog_type type;
	unsigned char pin;
	int map_prog_idx;
	struct bpf_program *prog;
};

;

static struct bpf_progs_desc progs[] = {
	{ "xdp_rx_filter", BPF_PROG_TYPE_XDP, 0, -1, NULL },
	{ "xdp_tx_filter", BPF_PROG_TYPE_SCHED_CLS, 1, -1, NULL },
};

int main(int argc, char *argv[])
{
	struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
	int base_fd, rx_prog_fd, tx_prog_fd, xdp_main_prog_fd;
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

	// load rex obj
	obj = rex_obj_get_bpf(rex_obj_load(EXE));
	if (!obj) {
		fprintf(stderr, "Object could not be opened\n");
		return 1;
	}

	rx_prog = bpf_object__find_program_by_name(obj, "xdp_rx_filter");
	if (!rx_prog) {
		fprintf(stderr, "start not found\n");
		return 1;
	}

	xdp_main_prog_fd = bpf_program__fd(rx_prog);
	if (xdp_main_prog_fd < 0) {
		fprintf(stderr, "Error: bpf_program__fd failed\n");
		return 1;
	}

	// Some nics do not support XDP DRV mode
	// xdp_flags |= XDP_FLAGS_DRV_MODE;
	xdp_flags |= XDP_FLAGS_SKB_MODE;
	for (int i = 0; i < interface_count; i++) {
		if (bpf_xdp_attach(interfaces_idx[i], xdp_main_prog_fd,
				   xdp_flags, NULL) < 0) {
			fprintf(stderr,
				"Error: bpf_set_link_xdp_fd failed for interface %d\n",
				interfaces_idx[i]);
			return 1;
		} else {
			printf("Main BPF program attached to XDP on interface %d\n",
			       interfaces_idx[i]);
		}
	}

	// binding sched_cls program
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

	// unattach program
	for (int i = 0; i < interface_count; i++)
		bpf_xdp_detach(interfaces_idx[i], xdp_flags, NULL);

	return ret;
}
