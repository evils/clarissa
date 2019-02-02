#include <arpa/inet.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct v6_addr {
  int netmask;
  uint8_t address[16];
};


int parse_addr(char* addr, struct v6_addr *dest) {
  char *netmask_ptr, *end;
  int retval;
  
  if (NULL != (netmask_ptr = strchr(addr, '/'))) {
    *netmask_ptr++ = 0;
    dest->netmask = strtol(netmask_ptr, &end, 10);
    if (end == netmask_ptr) {
      retval = 0;
      goto end;
    } else if (*end) {
      retval = 0;
      goto end;
    }
  } else {
    dest->netmask = 128;
  }

  // parse address
  if (inet_pton(AF_INET6, addr, dest->address)) {
    retval = 1;
    goto end;
  } else if (inet_pton(AF_INET, addr, dest->address + 12)) {
    memset(dest->address, 0, 10);
    memset(dest->address + 10, 0xFF, 2);
    dest->netmask += 12;
    retval = 1;
    goto end;
  } else {
    retval = 0;
    goto end;
  }

  abort();
  
 end:
  if (netmask_ptr != NULL) {
    *--netmask_ptr = '/';
  }
  return retval;
}

int main(int argc, char** argv) {
  struct v6_addr addr;

  
  if (parse_addr(argv[1], &addr)) {
    for (int i = 0; i < 16; i++) {
      if (i && !(i % 2)) {
    putchar(':');
      }
      printf("%02x", addr.address[i]);
    }
    printf("/%d\n", addr.netmask);
  } else {
    err(1, "Failed to parse address");
  }
  return 0;
}
