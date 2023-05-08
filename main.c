#include <stdio.h>

#include "dns.h"

int main(int argc, char *argv[]) {
    printf("Hello World!\n");
    dns_request("google.com", "1.1.1.1", 53);
    return 0;
}
