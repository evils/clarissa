SHELL = /usr/bin/env sh
CFLAGS = -Wall -g
LDFLAGS= -lpcap
clarissa: main.o clarissa.o time_tools.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	gcc $(CFLAGS) -c $<
clean:
	rm -rf clarissa main.o clarissa.o time_tools.o
