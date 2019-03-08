variant=debug

ifeq ($(variant),debug)
CFLAGS = -g -O0
endif
ifeq ($(variant),release)
CFLAGS = -O3
endif

OUTDIR = out/$(variant)

CFLAGS += -Iinclude -Wall

ALL_SRCS := $(shell find src -type f -name "*.c")
ALL_TEST := $(shell find test -type f -name "*.c")

all: $(OUTDIR)/libtq.a
	[ -h out/build ] && rm out/build || true
	[ -e out/build ] || ln -s $(variant) out/build

check: $(OUTDIR)/test_libtq
	prove $(OUTDIR)/test_libtq

$(OUTDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTDIR)/libtq.a: $(ALL_SRCS:%.c=$(OUTDIR)/%.o)
	if test -f $@; then rm $@; fi
	ar crv $@ $^

$(OUTDIR)/test_libtq: $(ALL_TEST:%.c=$(OUTDIR)/%.o) $(OUTDIR)/libtq.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -rf $(OUTDIR)
