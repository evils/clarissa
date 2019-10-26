CFLAGS= -pedantic -Wall -Wextra -g
LDFLAGS= -lpcap

.PHONY: all
all: clean test

test: test.o get_mac.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f test *.o
