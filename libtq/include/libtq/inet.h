#pragma once

#include <stdint.h>
#include <stdbool.h>

bool tq_inet_v6_subnet_check(uint8_t *address, uint8_t *network, uint8_t netmask);
