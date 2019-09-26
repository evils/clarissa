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

DESTDIR =
PREFIX = /usr
SYSDIR = /lib/systemd/system
SYSDINST = true
.PHONY: install
install: clarissa
	mkdir -p $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/man/man1 $(DESTDIR)$(PREFIX)/share/man/man8
	install clarissa $(DESTDIR)$(PREFIX)/sbin/clarissa
	install clar_count.sh $(DESTDIR)$(PREFIX)/bin/clar_count
	install clar_count.1 $(DESTDIR)$(PREFIX)/share/man/man1/clar_count.1
	install clarissa.8  $(DESTDIR)$(PREFIX)/share/man/man8/clarissa.8
	if $(SYSDINST); then mkdir -p $(DESTDIR)$(SYSDIR) && install clarissa.service $(DESTDIR)$(SYSDIR)/clarissa.service; fi
.PHONY: uninstall
uninstall:
	systemctl stop clarissa
	rm -rf /tmp/clar_*
	rm -rf $(DESTDIR)$(PREFIX)/sbin/clarissa
	rm -rf $(DESTDIR)$(PREFIX)/bin/clar_count
	rm -rf $(DESTDIR)$(PREFIX)/share/man/man1/clar_count.1.gz
	rm -rf $(DESTDIR)$(PREFIX)/share/man/man8/clarissa.8.gz
	if $(SYSDINST); then rm -rf $(DESTDIR)$(SYSDIR)/clarissa.service; fi

# uses pycflow2dot (from pip)
.PHONY: graph
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

index.html: README.md
	markdown -f +fencedcode README.md > index.html

.PHONY: clean
clean:
	rm -rf clarissa clarissa_static *.o cflow* $(OUTDIR)
