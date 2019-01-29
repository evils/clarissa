SHELL = /usr/bin/env sh
CFLAGS = -Wall -g
LDFLAGS= -lpcap
all: clean clarissa
clarissa: main.o clarissa.o time_tools.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<
clean:
	rm -rf clarissa main.o clarissa.o time_tools.o
