SHELL = /usr/bin/env sh
CFLAGS = -pedantic -Wall -Wextra -g
LDFLAGS= -lpcap

all: clean clarissa

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

# tests
OUTDIR = out
TEST_CFLAGS = -I libtq/include
ALL_SRCS := $(shell find libtq/src/test -type f -name "*.c")
ALL_SRCS += libtq/test/test_main.c
ALL_SRCS += $(wildcard *.c)
ALL_TEST := $(shell find test -type f -name "*.c")

test: $(OUTDIR)/clar_test check

check:
	prove -v $(OUTDIR)/clar_test

$(OUTDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -c -o $@ $<

$(OUTDIR)/libtq.a: $(ALL_SRCS:%.c=$(OUTDIR)/%.o)
	if test -f $@; then rm $@; fi
	ar crv $@ $^

$(OUTDIR)/clar_test: $(ALL_TEST:%.c=$(OUTDIR)/%.o) $(OUTDIR)/libtq.a
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf clarissa clarissa_static *.o cflow* test_sum.c $(OUTDIR)
