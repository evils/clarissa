SHELL = /usr/bin/env sh
CFLAGS = -pedantic -Wall -Wextra -g
LDFLAGS = -lpcap
OBJS = main.o clarissa.o time_tools.o get_hardware_address.o

.PHONY: all
all: clean clarissa

clarissa: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<
get_hardware_address.o: get_hardware_address/get_hardware_address.c
	$(CC) $(CFLAGS) -c $<

.PHONY: static
static: $(OBJS)
	$(CC) $(CFLAGS) -static -o clarissa_static $(OBJS) $(LDFLAGS)

DESTDIR =
PREFIX = /usr
SYSDIR = /lib/systemd/system
SYSDINST = true
DOCDIR = docs
.PHONY: install
install: clarissa man
	mkdir -p $(DESTDIR)$(PREFIX)/sbin $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/man/man1 $(DESTDIR)$(PREFIX)/share/man/man8
	install clarissa $(DESTDIR)$(PREFIX)/sbin/clarissa
	install $(DOCDIR)/clarissa-cat.1  $(DESTDIR)$(PREFIX)/share/man/man1/clarissa-cat.1
	install $(DOCDIR)/clarissa.8  $(DESTDIR)$(PREFIX)/share/man/man8/clarissa.8
	if $(SYSDINST); then mkdir -p $(DESTDIR)$(SYSDIR) && install clarissa.service $(DESTDIR)$(SYSDIR)/clarissa.service; fi
.PHONY: uninstall
uninstall:
	systemctl stop clarissa
	rm -rf /tmp/clar_*
	rm -rf $(DESTDIR)$(PREFIX)/sbin/clarissa
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
ALL_SRCS += get_hardware_address/get_hardware_address.c
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
.PHONY: index.html
index.html: README.adoc
	asciidoctor -o $@ $<

.PHONY: man
man: $(DOCDIR)/clarissa.8 $(DOCDIR)/clarissa-cat.1

$(DOCDIR)/clarissa.8: $(DOCDIR)/clarissa.adoc
	asciidoctor -b manpage $<

$(DOCDIR)/clarissa-cat.1: $(DOCDIR)/clarissa-cat.adoc
	asciidoctor -b manpage $<

.PHONY: clean
clean:
	rm -rf clarissa clarissa_static *.o cflow* $(OUTDIR) index.html
	rm -rf docs/*.[0-9]
