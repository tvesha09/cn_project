#include <stdio.h>

#include "interfaces.h"
#include "lpm.h"
#include "arp.h"

void packet_handler(int sock_fd, const char *iface, void *buf, int len);

int main(void)
{
    printf("=== Userspace IP Router ===\n");

    lpm_init();
    arp_init();
    interfaces_init();

    printf("[MAIN] Router initialized\n");

    interfaces_start_listeners(packet_handler);

    interfaces_close();

    return 0;
}