#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <librex.h>
#include <libbpf.h>

#define EXE "./target/x86_64-unknown-none/release/error_injector"

#define USAGE "./loader <syscall> <errno>\n"

int main(int argc, char *argv[])
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link = NULL;
	struct bpf_map *pid_to_errno;
	struct rex_obj *rex_obj;
	unsigned long errno_to_inject;
	int pid;
	LIBBPF_OPTS(bpf_ksyscall_opts, opts);

	if (argc < 3) {
		fprintf(stderr, USAGE);
		return 1;
	}

	errno_to_inject = -strtoul(argv[2], NULL, 10);

	rex_set_debug(1);

	rex_obj = rex_obj_load(EXE);
	if (!rex_obj) {
		fprintf(stderr, "rex_obj_load failed\n");
		return 1;
	}

	obj = rex_obj_get_bpf(rex_obj);
	if (!obj) {
		fprintf(stderr, "rex_obj_get_bpf failed\n");
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "err_injector");
	if (!prog) {
		fprintf(stderr, "bpf_object__find_program_by_name failed\n");
		return 1;
	}

	opts.retprobe = 0;
	link = bpf_program__attach_ksyscall(prog, argv[1], &opts);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		return 1;
	}

	pid_to_errno = bpf_object__find_map_by_name(obj, "pid_to_errno");
	if (libbpf_get_error(pid_to_errno)) {
		fprintf(stderr, "ERROR: Could not find map: pid_map\n");
		goto cleanup;
	}

	pid = fork();

	if (pid < 0) {
		perror("fork");
	} else if (!pid) {
		pid = getpid();
		if (bpf_map__update_elem(
			    pid_to_errno, &pid, sizeof(pid), &errno_to_inject,
			    sizeof(errno_to_inject), BPF_ANY) < 0) {
			fprintf(stderr, "ERROR: updating pid_map failed\n");
		}

		bpf_link__destroy(link);

		execl("./userapp", "./userapp", NULL);
		perror("executing userapp failed");
		return 1;
	}

	wait(NULL);

cleanup:
	bpf_link__destroy(link);
	return 0;
}
