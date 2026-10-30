CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -pthread

SRC = src/lpm.c src/arp.c src/interfaces.c src/router_core.c src/icmp.c src/checksum.c src/packet.c src/main.c
OBJ = $(SRC:.c=.o)

all: router test_client benchmark_lpm test_arp

router: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

test_client: test/test_client.c src/icmp.o src/checksum.o src/packet.o src/arp.o
	$(CC) $(CFLAGS) -o $@ $^

benchmark_lpm: test/benchmark_lpm.c src/lpm.c
	$(CC) $(CFLAGS) -o $@ $^

test_arp: test/test_arp.c src/arp.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f src/*.o test/*.o router test_client benchmark_lpm test_arp

.PHONY: all clean test_arp
