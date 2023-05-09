#include <stdio.h>

#include "dns.h"

int main(int argc, char *argv[]) {
    if (dns_request("agtkh.com", "1.1.1.1", 53) == -1) {
        fprintf(stderr, "dns_request failed\n");
        return -1;
    }
    return 0;
}
