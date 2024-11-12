#define _DEFAULT_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <linux/unistd.h>

int main(void)
{
	if (syscall(__NR_dup, 0) < 0) {
		perror("dup");
	}
}
