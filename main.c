#include <stdio.h>
#include <stdlib.h>

#include "dns.h"

int main(int argc, char *argv[]) {
    // default dns server is
    char *dns_server_addr = "8.8.8.8";
    int dns_server_port = 53;

    _Bool use_mdns = 1;

    // check arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <domain> [dns_server_addr] [dns_server_port]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc > 2) {
        dns_server_addr = argv[2];
        use_mdns = 0;
    }
    if (argc > 3) {
        dns_server_port = atoi(argv[3]);
    }

    // send dns request
    printf("DNS Server:\t%s#%d\n", dns_server_addr, dns_server_port);
    if (dns_request(argv[1], dns_server_addr, dns_server_port) == -1) {
        fprintf(stderr, "dns_request failed\n");
        return EXIT_FAILURE;
    }

    // send mdns request
    if (use_mdns) {
        printf("\nMulticast DNS (mDNS)\n");
        if (mdns_request(argv[1]) == -1) {
            fprintf(stderr, "mdns_request failed\n");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
