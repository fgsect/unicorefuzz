#include <stdlib.h>
#include <stdio.h>

static size_t write_callback(void* file, char* buf, size_t len, void* offset) {
    if (buf[0] == 'A') {
        int a = 2;
        //a -= 2;
        if (5/a > 0) {
            printf("nop\n");
        }
    }
}
void main() {
    char input[1024];
    fgets(input, 256, stdin);
    write_callback(0, input, 0, 0);
}
