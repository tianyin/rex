#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	int nr_rounds, arg, fd;

	if (argc != 3)
		asm volatile ("ud2");

	nr_rounds = atoi(argv[1]);
	arg = atoi(argv[2]);
	fd = open("/proc/kprobe_target", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	for (int i = 0; i < nr_rounds; i++)
		ioctl(fd, 1313, arg);

	close(fd);
}
