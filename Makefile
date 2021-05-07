SHELL = /bin/sh
# this Makefile only works with GNU Make!

# build
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

clar_OUI.csv: utils/matcrc
	utils/OUI_assemble.sh
utils/matcrc: $(SRCDIR)/matcrc64min.c
	$(CC) $(CFLAGS) -o $@ $^


# install
DESTDIR =
PREFIX = /usr
SYSDIR = /lib/systemd/system
DOCDIR = docs

.PHONY: install
install: install-clarissa install-sysd install-oui install-clar
.PHONY: install-clarissa
install-clarissa: clarissa man
	install -D clarissa $(DESTDIR)$(PREFIX)/bin/clarissa
	install -D $(DOCDIR)/clarissa-cat.1  $(DESTDIR)$(PREFIX)/share/man/man1/clarissa-cat.1
	install -D $(DOCDIR)/clarissa.8  $(DESTDIR)$(PREFIX)/share/man/man8/clarissa.8
.PHONY: install-clar
install-clar: man
	install -D utils/clar.sh $(DESTDIR)$(PREFIX)/bin/clar
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	install -D $(DOCDIR)/clar.1 $(DOCDIR)/clar-*.1 $(DESTDIR)$(PREFIX)/share/man/man1
.PHONY: install-oui
install-oui: clar_OUI.csv
	install -D clar_OUI.csv $(DESTDIR)$(PREFIX)/share/misc/clar_OUI.csv
.PHONY: install-sysd
install-sysd:
	install -D clarissa.service $(DESTDIR)$(SYSDIR)/clarissa.service
.PHONY: uninstall
uninstall:
	rm -rf $(DESTDIR)$(PREFIX)/bin/clarissa
	rm -rf $(DESTDIR)$(PREFIX)/share/man/man1/clarissa-cat.1*
	rm -rf $(DESTDIR)$(PREFIX)/share/man/man8/clarissa.8*
	if $(SYSDINST); then systemctl stop clarissa; rm -f $(DESTDIR)$(SYSDIR)/clarissa.service; fi
	if $(GETOUI); then rm -f $(DESTDIR)$(PREFIX)/share/misc/clar_OUI.csv; fi
	if $(CLAR); then rm -f $(CLARDIR)$(PREFIX)/bin/clar; \
		$(CLARDIR)$(PREFIX)/share/man/man1/clar.1; \
		$(CLARDIR)$(PREFIX)/share/man/man1/clar-*.1; \
	fi


# trivia
.PHONY: static
static: main.o clarissa.o time_tools.o get_hardware_address.o clarissa_cat.o
	$(CC) $(CFLAGS) -static -o clarissa_static $^ $(LDFLAGS)

# uses cflow2dot (from pycflow2dot)
.PHONY: graph
graph:
	rm -f cflow_sum.c
	cat $(SRCDIR)/*.c > cflow_sum.c
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


# docs
.PHONY: index.html
index.html: README.adoc
	asciidoctor -o $@ $<

.PHONY: clarissa-man
man: $(DOCDIR)/clarissa.8 $(DOCDIR)/clarissa-cat.1
.PHONY: clar-man
man: $(DOCDIR)/clar.1 $(DOCDIR)/clar-count.1 $(DOCDIR)/clar-show.1 $(DOCDIR)/clar-scan.1 $(DOCDIR)/clar-sort.1

$(DOCDIR)/clarissa.8: $(DOCDIR)/clarissa.adoc
	asciidoctor -b manpage $<
$(DOCDIR)/clarissa-cat.1: $(DOCDIR)/clarissa-cat.adoc
	asciidoctor -b manpage $<
$(DOCDIR)/clar.1: $(DOCDIR)/clar.adoc
	asciidoctor -b manpage $<
$(DOCDIR)/clar-%.1: $(DOCDIR)/clar-%.adoc
	asciidoctor -b manpage $<


# cleaning
.PHONY: clean
clean:
	rm -rf clarissa clarissa_static
	rm -rf *.o $(OUTDIR)
	rm -rf docs/*.[0-9] index.html
	rm -rf clar_OUI.csv
	rm -rf matcrc utils/matcrc
	rm -rf cflow*
