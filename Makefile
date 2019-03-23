SHELL = /usr/bin/env sh
CFLAGS = -pedantic -Wall -Wextra -g
LDFLAGS= -lpcap
clarissa: main.o clarissa.o time_tools.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# uses pycflow2dot (from pip)
graph:
	cat *.c > test_sum.c
	cflow2dot -i test_sum.c -f svg

all: clean clarissa
clean:
	rm -rf clarissa main.o clarissa.o time_tools.o cflow* test_sum.c
