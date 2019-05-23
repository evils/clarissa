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
	rm -f cflow_sum.c
	cat *.c > cflow_sum.c
	cflow2dot -i cflow_sum.c -f svg
	rm -f cflow_sum.c

# tests
OUTDIR = out
ALL_SRCS := $(wildcard *.c)
ALL_TEST := $(shell find test -type f -name "*.c")


.PHONY: check test
test check: $(OUTDIR)/clar_test
	prove -v $(OUTDIR)/clar_test

$(OUTDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -c -o $@ $<

ifeq ($(USE_SYSTEM_LIBTQ),)
ALL_SRCS += $(shell find libtq/src/test -type f -name "*.c")
ALL_SRCS += libtq/test/test_main.c
LIBTQ_DEP = $(OUTDIR)/libtq.a
TEST_CFLAGS += -I libtq/include

$(OUTDIR)/libtq.a: $(ALL_SRCS:%.c=$(OUTDIR)/%.o)
	if test -f $@; then rm $@; fi
	ar crv $@ $^

else
LIBTQ_DEP =
LDFLAGS += -ltq
endif

$(OUTDIR)/clar_test: $(ALL_TEST:%.c=$(OUTDIR)/%.o) $(LIBTQ_DEP)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) -o $@ $^ $(LDFLAGS)

# not tests

html: README.md
	markdown -f +fencedcode README.md > index.html

clean:
	rm -rf clarissa clarissa_static *.o cflow* $(OUTDIR)
