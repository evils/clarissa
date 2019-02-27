OUTDIR = out

CFLAGS = -Iinclude -Wall -g

ALL_SRCS := $(shell find src -type f -name "*.c")
ALL_TEST := $(shell find test -type f -name "*.c")

all: out/libtq.a
check: out/test_libtq
	prove out/test_libtq

out/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

out/libtq.a: $(ALL_SRCS:%.c=out/%.o)
	if test -f $@; then rm $@; fi
	ar crv $@ $^

out/test_libtq: $(ALL_TEST:%.c=out/%.o) out/libtq.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
