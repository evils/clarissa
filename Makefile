CFLAGS= -pedantic -Wall -Wextra -g
LDFLAGS= -lpcap
OBJS= test.o get_hardware_address.o

.PHONY: all
all: clean test

test: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

.PHONY: check
check: test
	sudo ./test

.PHONY: index.html
index.html:
	asciidoctor README.adoc -o index.html

.PHONY: manual
manual:
	asciidoctor -b manpage README.adoc

.PHONY: clean
clean:
	rm -f test *.o get_hardware_address.3 index.html
