#include <unistd.h>
#include <linux/unistd.h>

int main(void)
{
    char buf[256];
    char *unused = getcwd(buf, 256);
    (void)unused;
    // printf("%s\n", buf);
    return 0;
}
