#include <stdio.h>

#include "interfaces.h"
#include "lpm.h"
#include "arp.h"
#include "router_core.h"

int main(void)
{
    printf("=== Userspace IP Router ===\n");

    lpm_init();
    arp_init();
    interfaces_init();
    router_start_timer();

    printf("[MAIN] Router initialized\n");

    interfaces_start_listeners(packet_handler);

    interfaces_close();

    return 0;
}