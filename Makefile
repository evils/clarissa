SHELL = /bin/sh
# this Makefile only works with GNU Make!

CFLAGS = -pedantic -Wall -Wextra -g
LDFLAGS = -lpcap
SRCDIR = src

ifeq '$(shell uname -s)' 'SunOS'
CFLAGS += -D__EXTENSIONS__	# funlockfile etc warnings
LDFLAGS += -lxnet		# socket etc functions ld errors
endif

.PHONY: all
all: clean clarissa clar_OUI.csv

clarissa: main.o clarissa.o time_tools.o get_hardware_address.o clarissa_cat.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $<
get_hardware_address.o: get_hardware_address/get_hardware_address.c
	$(CC) $(CFLAGS) -c $^

.PHONY: static
static: main.o clarissa.o time_tools.o get_hardware_address.o clarissa_cat.o
	$(CC) $(CFLAGS) -static -o clarissa_static $^ $(LDFLAGS)


DESTDIR =
PREFIX = /usr
SYSDIR = /lib/systemd/system
SYSDINST = true
DOCDIR = docs
GETOUI = true
CLAR = true
clar_OUI.csv: utils/matcrc
	if $(GETOUI); then utils/OUI_assemble.sh; fi
utils/matcrc: $(SRCDIR)/matcrc64min.c
	$(CC) $(CFLAGS) -o $@ $^
.PHONY: install
install: clarissa man
	mkdir -p $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/share/man/man1 $(DESTDIR)$(PREFIX)/share/man/man8
	install clarissa $(DESTDIR)$(PREFIX)/bin/clarissa
	install $(DOCDIR)/clarissa-cat.1  $(DESTDIR)$(PREFIX)/share/man/man1/clarissa-cat.1
	install $(DOCDIR)/clarissa.8  $(DESTDIR)$(PREFIX)/share/man/man8/clarissa.8
	if $(SYSDINST); then mkdir -p $(DESTDIR)$(SYSDIR) && cp clarissa.service $(DESTDIR)$(SYSDIR)/clarissa.service; fi
	if $(GETOUI); then mkdir -p $(DESTDIR)$(PREFIX)/share/clarissa && cp clar_OUI.csv $(DESTDIR)$(PREFIX)/share/clarissa/clar_OUI.csv; fi
	if $(CLAR); then mkdir -P $(DESTDIR)$(PREFIX)/lib/clarissa && cp utils/clar*.sh $(DESTDIR)$(PREFIX)/lib/clarissa/. && ln -s $(DESTDIR)$(PREFIX)/lib/clarissa/clar.sh $(DESTDIR)$(PREFIX)/bin/clar
.PHONY: uninstall
uninstall:
	rm -rf $(DESTDIR)$(PREFIX)/bin/clarissa
	rm -rf $(DESTDIR)$(PREFIX)/share/man/man1/clarissa-cat.1*
	rm -rf $(DESTDIR)$(PREFIX)/share/man/man8/clarissa.8*
	if $(SYSDINST); then systemctl stop clarissa; rm -rf $(DESTDIR)$(SYSDIR)/clarissa.service; fi

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

.PHONY: $(DOCDIR)/clarissa.adoc
$(DOCDIR)/clarissa.8: $(DOCDIR)/clarissa.adoc
	asciidoctor -b manpage $<

.PHONY: $(DOCDIR)/clarissa-cat.adoc
$(DOCDIR)/clarissa-cat.1: $(DOCDIR)/clarissa-cat.adoc
	asciidoctor -b manpage $<

.PHONY: clean
clean:
	rm -rf clarissa clarissa_static
	rm -rf *.o $(OUTDIR)
	rm -rf docs/*.[0-9] index.html
	rm -rf clar_OUI.csv
	rm -rf matcrc utils/matcrc
	rm -rf cflow*
