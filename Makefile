CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -pthread

SRC = src/lpm.c src/arp.c src/interfaces.c src/router_core.c src/main.c
OBJ = $(SRC:.c=.o)

all: router test_client

router: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

test_client: test/test_client.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f src/*.o test/*.o router test_client

.PHONY: all clean