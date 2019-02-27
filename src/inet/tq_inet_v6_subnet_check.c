#include <libtq/inet.h>
bool tq_inet_v6_subnet_check(uint8_t *address, uint8_t *network, uint8_t netmask) {
  if (netmask > 128) {
    netmask = 128;
  }
  
  while (netmask > 8) {
    if (*address++ != *network++) {
      return false;
    }
    netmask -= 8;
  }

  uint8_t byte_mask = (~(uint16_t)0xFF) >> netmask; // top $netmask bits are set
  return (*address & byte_mask) == (*network & byte_mask);
}
