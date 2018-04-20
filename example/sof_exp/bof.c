#include <stdio.h>
#include <string.h>
#include <unistd.h>

int i;
int bytes;
char input[1000];
int main()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    char buf[100];
    puts("input something");
    //scanf("%s", buf);
    bytes = read(0, input, 1000);
    memcpy(buf, input, bytes);
    for (i=0; i<bytes; i++)
    {
        buf[i] -= 0xa;
        buf[i] ^= 0x55;
        buf[i] += 1;
    }
    return 0;
}
