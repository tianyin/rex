#include <unistd.h>
#include <linux/unistd.h>
#include <stdio.h>

int main(void)
{
    setuid(1000);
    fprintf(stdout, "pid=%d\n", getpid());
    fprintf(stdout, "Before: uid=%ld, euid=%ld\n", syscall(__NR_getuid), syscall(__NR_geteuid));
    syscall(__NR_dup, 1);
    fprintf(stdout, "After: uid=%ld, euid=%ld\n", syscall(__NR_getuid), syscall(__NR_geteuid));
    return 0;
}