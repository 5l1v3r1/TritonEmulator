#include <stdio.h>
#include <unistd.h>

int main()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    char buf[100];
    puts("input something");
    //scanf("%s", buf);
    read(0, buf, 1000);
    return 0;
}
