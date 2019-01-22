SHELL = /usr/bin/env sh
CFLAGS = -Wall -g
LDFLAGS= -lpcap
clarissa: main.o get_addresses.o time_tools.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	gcc $(CFLAGS) -c $<
clean:
	rm clarissa main.o get_addresses.o time_tools.o
