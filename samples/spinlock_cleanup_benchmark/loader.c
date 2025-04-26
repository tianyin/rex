#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <linux/types.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <librex.h>

#define EXE "./target/x86_64-unknown-none/release/spinlock_cleanup_benchmark"

#define __unused __attribute__((__unused__))

int main(int __unused argc, char **argv)
{
	struct bpf_program *prog;
	struct bpf_object *obj;

	int interface_idx = atoi(argv[1]);
	unsigned int xdp_flags = 0;
	xdp_flags |= XDP_FLAGS_DRV_MODE;
	/* xdp_flags |= XDP_FLAGS_SKB_MODE; */

	obj = rex_obj_get_bpf(rex_obj_load(EXE));
	if (!obj) {
		fprintf(stderr, "Object could not be opened\n");
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "rex_prog1");
	if (!prog) {
		printf("finding a prog in obj file failed\n");
		return 1;
	}
	int xdp_main_prog_fd = bpf_program__fd(prog);

	if (bpf_xdp_attach(interface_idx, xdp_main_prog_fd, xdp_flags, NULL) <
	    0) {
		fprintf(stderr, "ERROR: xdp failed");
		return 1;
	}

	return 0;
}
