SHELL = /usr/bin/env sh
CFLAGS = -Wall -g
LDFLAGS= -lpcap
clarissa: main.o get_addresses.o
	gcc $(CFLAGS) $(LDFLAGS) -o $@ $^
%.o: %.c
	gcc $(CFLAGS) -c $<
clean:
	rm clarissa main.o get_addresses.o
