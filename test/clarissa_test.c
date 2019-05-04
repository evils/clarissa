#include <libtq/test.h>
#include "../clarissa.h"

TQ_TEST("net_puts")
{
	// 0b1000000000000001
	uint16_t source = 32769;
	// 0b0000000110000000
	uint16_t intent = 384;
	uint8_t target[2];

	net_puts((uint8_t*) &target, source);

	return !memcmp(&target, &intent, 2);
}

TQ_TEST("is_zeros")
{
	uint32_t zeros = 0;
	uint32_t one = 1;

	if (is_zeros((uint8_t*) &one, 4)) return 0;
	if (is_zeros((uint8_t*) &zeros, 4)) return 1;

	return 0;
}

TQ_TEST("is_mapped")
{
	uint8_t ip[16];
	memset(&ip, 0, 16);
	if (is_mapped((uint8_t*) &ip)) return 0;
	ip[10] = 0xFF;
	ip[11] = 0xFF;
	if (is_mapped((uint8_t*) &ip)) return 1;

	return 0;
}

TQ_TEST("subnet_check/ipv4/pass")
{
	uint8_t ip[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			  0x00, 0x00, 0xFF, 0xFF, 192, 168, 10, 1};
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 127,
		.ip = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0xFF, 0xFF, 192, 168, 10, 1 } };

	subnet_check((uint8_t*) &ip, &subnet);

	// .1 should be in the subnet .1, nothing should be changed
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_check/ipv4/fail")
{
	uint8_t ip[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			   0x00, 0x00, 0xFF, 0xFF, 192, 168, 10, 0 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 127,
		.ip = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0xFF, 0xFF, 192, 168, 10, 1 } };

	subnet_check((uint8_t*) &ip, &subnet);

	// .0 is not in .1, the entire ip should get zerod
	return !memcmp(&ip, &start, sizeof(ip));
}
