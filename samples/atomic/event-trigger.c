#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	int nr_rounds = argc == 2 ? atoi(argv[1]) : 1000;
	int fd = open("/proc/kprobe_target", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	for (int i = 0; i < nr_rounds; i++)
		ioctl(fd, 1313, 0);

	close(fd);
}
