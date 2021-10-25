#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "elf.h"

#define ERR(x...)                               \
    do {                                        \
        printf(x);                              \
        return 1;                               \
    } while(0);

#define MAX_PROG_SZ (8192 * 4)


long stub_bpf_trace_printk(const char *fmt, uint32_t fmt_size, ...) {
    va_list args;
    va_start(args, fmt_size);
    vprintf(fmt, args);
    va_end(args);
    return 0;
}
uint64_t stub_bpf_get_current_pid_tgid(void) {
    return 0xdeadbeefdeadbeef;
}
void stub_bpf_test_call(void) {
    printf("Hello world!\n");
}

int main(int argc, char **argv) {
    int fd;
    void *area;
    size_t sz, n;
 
    if (argc != 2)
        ERR("Usage: %s <prog>\n", argv[0]);

    fd = open(argv[1], O_RDONLY);
    if (!fd)
        ERR("Couldn't open file %s\n", argv[1]);

    printf("static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) %p;\n", stub_bpf_trace_printk);
    printf("static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) %p;\n", stub_bpf_get_current_pid_tgid);
    printf("static void (*bpf_test_call)(void) = (void *) %p;\n", stub_bpf_test_call);
        
    area = mmap(NULL, MAX_PROG_SZ,
                PROT_EXEC | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0);
    if (area == MAP_FAILED)
        ERR("Couldn't create map of size %d\n", MAX_PROG_SZ);
    printf("Area is at %p\n", area);
    uint64_t entry = 0;
    if (elf_load(fd, argv[1], area, MAX_PROG_SZ, &entry))
        ERR("Couldn't load\n");
    printf("Entry point is 0x%lx\n", entry);
    uint64_t (*run_prog)(void) = (uint64_t (*)(void))(area + entry);
    
    printf("Running %s...\n", argv[0]);
    run_prog();
    
    return 0;
}
