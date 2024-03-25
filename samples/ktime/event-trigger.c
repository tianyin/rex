#include <unistd.h>
#include <linux/unistd.h>

int main(void)
{
    char buf[256];
    getcwd(buf, 256);
    // printf("%s\n", buf);
    return 0;
}
