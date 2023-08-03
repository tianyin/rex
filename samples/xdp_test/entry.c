

#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
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

#define EXE "./target/debug/xdp_test"

static int nr_cpus = 0;

struct bpf_progs_desc {
  char name[256];
  enum bpf_prog_type type;
  unsigned char pin;
  int map_prog_idx;
  struct bpf_program *prog;
};

static struct bpf_progs_desc progs[] = {
    {"bmc_rx_filter", BPF_PROG_TYPE_XDP, 0, -1, NULL},
    // {"bmc_hash_keys", BPF_PROG_TYPE_XDP, 0, BMC_PROG_XDP_HASH_KEYS, NULL},
    // {"bmc_prepare_packet", BPF_PROG_TYPE_XDP, 0,
    // BMC_PROG_XDP_PREPARE_PACKET, NULL},
    // {"bmc_write_reply", BPF_PROG_TYPE_XDP, 0, BMC_PROG_XDP_WRITE_REPLY,
    // NULL},
    // {"bmc_invalidate_cache", BPF_PROG_TYPE_XDP, 0,
    // BMC_PROG_XDP_INVALIDATE_CACHE, NULL},

    {"xdp_tx_filter", BPF_PROG_TYPE_SCHED_CLS, 1, -1, NULL},
    // {"bmc_update_cache", BPF_PROG_TYPE_SCHED_CLS, 0,
    // BMC_PROG_TC_UPDATE_CACHE, NULL},
};

int main(int argc, char *argv[]) {
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
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

  iu_set_debug(1);  // enable debug info

  interface_count = argc - optind;
  if (interface_count <= 0) {
    fprintf(stderr, "Missing at least one required interface index\n");
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
  for (int i = 0; i < interface_count; i++) {
    if (bpf_set_link_xdp_fd(interfaces_idx[i], xdp_main_prog_fd, xdp_flags) <
        0) {
      fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n",
              interfaces_idx[i]);
      return 1;
    } else {
      printf("Main BPF program attached to XDP on interface %d\n",
             interfaces_idx[i]);
    }
  }

	tx_prog = bpf_object__find_program_by_name(obj, "xdp_tx_filter");

  int len =
      snprintf(filename, PATH_MAX, "%s/%s", BPF_SYSFS_ROOT, "xdp_tx_filter");
  if (len < 0) {
      fprintf(stderr, "Error: Program name '%s' is invalid\n", "xdp_tx_filter");
      return -1;
  } else if (len >= PATH_MAX) {
      fprintf(stderr, "Error: Program name '%s' is too long\n",
              "xdp_tx_filter");
      return -1;
  }

  if (bpf_program__pin_instance(tx_prog, filename, 0)) {
      fprintf(stderr, "Error: Failed to pin program '%s' to path %s\n",
              "xdp_tx_filter", filename);
      if (errno == EEXIST) {
        fprintf(stdout,
                "BPF program '%s' already pinned, unpinning it to reload it\n",
                "xdp_tx_filter");
        if (bpf_program__unpin_instance(tx_prog, filename, 0)) {
          fprintf(stderr, "Error: Fail to unpin program '%s' at %s\n",
                  "xdp_tx_filter", filename);
          return -1;
        }
      }
      return -1;
  }
  // for (int i = 0; i < interface_count; i++) {
  //     bpf_set_link_xdp_fd(interfaces_idx[i], -1, xdp_flags);
  // }
  return ret;
}
