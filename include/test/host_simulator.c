
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define HOST_PORT 9001
#define ROUTER_PORT 8001

int main(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in host_addr = {0};
    host_addr.sin_family = AF_INET;
    host_addr.sin_port = htons(HOST_PORT);
    host_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&host_addr,
             sizeof(host_addr)) < 0) {
        perror("bind");
        close(sock);
        return 1;
    }

    printf("Host simulator listening on UDP port %d\n", HOST_PORT);

    char buffer[2048];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);

    while (1) {
        ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0,
                             (struct sockaddr *)&sender, &sender_len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }

        printf("Received %zd bytes from %s:%d\n",
               n, inet_ntoa(sender.sin_addr),
               ntohs(sender.sin_port));
    }

    close(sock);
    return 0;
}

