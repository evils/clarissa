SHELL = /usr/bin/env sh
CFLAGS = -pedantic -Wall -Wextra -g
LDFLAGS= -lpcap
clarissa: main.o clarissa.o time_tools.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

static: main.o clarissa.o time_tools.o
	$(CC) $(CFLAGS) -static -o clarissa_static $^ $(LDFLAGS)

# uses pycflow2dot (from pip)
graph:
	rm test_sum.c
	cat *.c > test_sum.c
	cflow2dot -i test_sum.c -f svg

all: clean clarissa
clean:
	rm -rf clarissa clarissa_static *.o cflow* test_sum.c
