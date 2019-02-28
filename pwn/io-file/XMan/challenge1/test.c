#include <stdio.h>

int main()
{
    int x;
    FILE *stream = fopen("test.txt", "r");
    if(x == 3)
        fclose(stream);
    return 0;
}
