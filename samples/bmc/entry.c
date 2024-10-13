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
#include <assert.h>

#include <librex.h>

#define BPF_SYSFS_ROOT "/sys/fs/bpf"

#define STATS_PATH "/tmp/rust_bmc_stats.txt"
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

struct bmc_stats {
	unsigned int get_recv_count; // Number of GET command received
	unsigned int set_recv_count; // Number of SET command received
	unsigned int get_resp_count; // Number of GET command reply analyzed
	unsigned int
		hit_misprediction; // Number of keys that were expected to hit but did not (either because of a hash colision or a race with an invalidation/update)
	unsigned int hit_count; // Number of HIT in kernel cache
	unsigned int miss_count; // Number of MISS in kernel cache
	unsigned int update_count; // Number of kernel cache updates
	unsigned int
		invalidation_count; // Number of kernel cache entry invalidated
	unsigned int debug_count;
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

int write_stats_to_file(char *filename, int map_fd)
{
	struct bmc_stats stats[nr_cpus];
	struct bmc_stats aggregate_stats;
	__u32 key = 0;
	FILE *fp;

	memset(&aggregate_stats, 0, sizeof(struct bmc_stats));

	assert(bpf_map_lookup_elem(map_fd, &key, stats) == 0);
	for (int i = 0; i < nr_cpus; i++) {
		aggregate_stats.get_recv_count += stats[i].get_recv_count;
		aggregate_stats.set_recv_count += stats[i].set_recv_count;
		aggregate_stats.get_resp_count += stats[i].get_resp_count;
		aggregate_stats.hit_misprediction += stats[i].hit_misprediction;
		aggregate_stats.hit_count += stats[i].hit_count;
		aggregate_stats.miss_count += stats[i].miss_count;
		aggregate_stats.update_count += stats[i].update_count;
		aggregate_stats.invalidation_count +=
			stats[i].invalidation_count;
		aggregate_stats.debug_count += stats[i].debug_count;
	}

	fp = fopen(STATS_PATH, "w+");
	if (fp == NULL) {
		fprintf(stderr, "Error: failed to write stats to file '%s'\n",
			filename);
		return -1;
	}

	fprintf(fp, "STAT get_recv_count %u\n", aggregate_stats.get_recv_count);
	fprintf(fp, "STAT set_recv_count %u\n", aggregate_stats.set_recv_count);
	fprintf(fp, "STAT get_resp_count %u\n", aggregate_stats.get_resp_count);
	fprintf(fp, "STAT hit_misprediction %u\n",
		aggregate_stats.hit_misprediction);
	fprintf(fp, "STAT hit_count %u\n", aggregate_stats.hit_count);
	fprintf(fp, "STAT miss_count %u\n", aggregate_stats.miss_count);
	fprintf(fp, "STAT update_count %u\n", aggregate_stats.update_count);
	fprintf(fp, "STAT invalidation_count %u\n",
		aggregate_stats.invalidation_count);
	fprintf(fp, "STAT debug_count %u\n", aggregate_stats.debug_count);
	fclose(fp);
	return 0;
}

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

	libbpf_set_print(libbpf_print_fn);
	rex_set_debug(1); // enable debug info

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

	xdp_flags |= XDP_FLAGS_DRV_MODE;
	/* xdp_flags |= XDP_FLAGS_SKB_MODE; */
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

	int map_stats_fd = bpf_object__find_map_fd_by_name(obj, "map_stats");
	if (map_stats_fd < 0) {
		fprintf(stderr,
			"Error: bpf_object__find_map_fd_by_name failed\n");
		return 1;
	}

	printf("Writing stats to file\n");
	write_stats_to_file(STATS_PATH, map_stats_fd);

	for (int i = 0; i < interface_count; i++) {
		bpf_xdp_attach(interfaces_idx[i], -1, xdp_flags, NULL);
	}
	return ret;
}
