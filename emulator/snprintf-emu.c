#include <stdio.h>

int bbfw_snprintf(char *, size_t, const char *, ...);
//int bbfw_sprintf(char *, const char *, ...);

int main(int argc, char **argv) {
    char buffer[64];
    buffer[0] = '\0';
    int ret = bbfw_snprintf(buffer, sizeof buffer, "%s %s - the answer is %d", "hello", "world!", 42);
    //int ret = bbfw_sprintf(buffer, "%s %s - the answer is %d", "hello", "world!", 42);
    printf("ret=%d\n", ret);
    printf("buffer=%s\n", buffer);
    return 0;
}
