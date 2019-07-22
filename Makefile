SHELL = /usr/bin/env sh
CFLAGS = -pedantic -Wall -Wextra -g
LDFLAGS= -lpcap

.PHONY: all
all: clean clarissa

clarissa: main.o clarissa.o time_tools.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

.PHONY: static
static: main.o clarissa.o time_tools.o
	$(CC) $(CFLAGS) -static -o clarissa_static $^ $(LDFLAGS)

# uses pycflow2dot (from pip)
graph:
	rm -f cflow_sum.c
	cat *.c > cflow_sum.c
	cflow2dot -i cflow_sum.c -f svg
	rm -f cflow_sum.c

# tests
OUTDIR = out
TEST_CFLAGS = -I libtq/include
ALL_SRCS := $(shell find libtq/src/test -type f -name "*.c")
ALL_SRCS += libtq/test/test_main.c
ALL_SRCS += $(wildcard *.c)
ALL_TEST := $(shell find test -type f -name "*.c")


.PHONY: check test
test check: $(OUTDIR)/clar_test
	prove -v $(OUTDIR)/clar_test

$(OUTDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -c -o $@ $<

$(OUTDIR)/libtq.a: $(ALL_SRCS:%.c=$(OUTDIR)/%.o)
	if test -f $@; then rm $@; fi
	ar crv $@ $^

$(OUTDIR)/clar_test: $(ALL_TEST:%.c=$(OUTDIR)/%.o) $(OUTDIR)/libtq.a
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -o $@ $^ $(LDFLAGS)

# not tests

html: README.md
	markdown -f +fencedcode README.md > index.html

.PHONY: clean
clean:
	rm -rf clarissa clarissa_static *.o cflow* $(OUTDIR)
