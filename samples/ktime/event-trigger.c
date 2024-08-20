#include <unistd.h>
#include <linux/unistd.h>

int main(void)
{
    char buf[256];
    char *result = getcwd(buf, 256);
    (void)result;
    return 0;
}
