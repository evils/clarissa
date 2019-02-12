SHELL = /usr/bin/env sh
CFLAGS = -Wall -g
LDFLAGS= -lpcap
clarissa: main.o clarissa.o time_tools.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<
all: clean clarissa
clean:
	rm -rf clarissa main.o clarissa.o time_tools.o
