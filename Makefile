CFLAGS= -pedantic -Wall -Wextra -g
LDFLAGS= -lpcap

.PHONY: all
all: clean test

test: test.o get_hardware_address.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $<

index.html:
	asciidoctor README.adoc -o index.html

.PHONY: manual
manual:
	asciidoctor -b manpage README.adoc

.PHONY: clean
clean:
	rm -f test *.o get_hardware_address.3 index.html
