#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sched.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <linux/types.h>
#include <linux/if_link.h>

#include <bpf.h>
#include <libbpf.h>

#include "libiu.h"

#define EXE "./target/x86_64-unknown-linux-gnu/release/spinlock_cleanup_benchmark"

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[256];
	iu_set_debug(1); // enable debug info
	int ret;

	int interface_idx = atoi(argv[1]);
	unsigned int xdp_flags = 0;
	xdp_flags |= XDP_FLAGS_SKB_MODE;

	obj = iu_object__open(EXE);
	if (!obj) {
		fprintf(stderr, "Object could not be opened\n");
		exit(1);
	}

	prog = bpf_object__find_program_by_name(obj, "iu_prog1");
	if (!prog) {
		printf("finding a prog in obj file failed\n");
		goto cleanup;
	}
	int xdp_main_prog_fd = bpf_program__fd(prog);

	if (bpf_set_link_xdp_fd(interface_idx, xdp_main_prog_fd, xdp_flags) < 0) {
		fprintf(stderr, "ERROR: xdp failed");
	}


cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
