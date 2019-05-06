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

	return !memcmp(&target, &intent, sizeof(target));
}

TQ_TEST("is_zeros/pass")
{
	uint32_t zero = 0;

	return is_zeros((uint8_t*) &zero, 4);
}

TQ_TEST("is_zeros/fail")
{
	uint32_t one = 1;

	return !is_zeros((uint8_t*) &one, 4);
}

TQ_TEST("is_mapped")
{
	uint8_t ip[16];
	memset(&ip, 0, sizeof(ip));
	if (is_mapped((uint8_t*) &ip)) return 0;
	memset(ip+10, 0xFF, 2);
	if (is_mapped((uint8_t*) &ip)) return 1;

	return 0;
}

TQ_TEST("bitcmp/pass/0")
{
	uint8_t a[2] = { 0, 128 };
	uint8_t b[3] = { 0, 192, 0 };
	int n = 9;

	return !bitcmp(a, b, n);
}

TQ_TEST("bitcmp/pass/1")
{
	uint8_t a[2] = { 0, 1 };
	uint8_t b[3] = { 0, 0, 0 };
	int n = 15;

	return !bitcmp(a, b, n);
}

TQ_TEST("bitcmp/fail/0")
{
	uint8_t a[2] = { 0, 128 };
	uint8_t b[3] = { 0, 0, 0 };
	int n = 9;

	return bitcmp(a, b, n);
}

TQ_TEST("bitcmp/fail/1")
{
	uint8_t a[2] = { 0, 1 };
	uint8_t b[3] = { 0, 0, 0 };
	int n = 16;

	return bitcmp(a, b, n);
}

TQ_TEST("subnet_check/ipv4/pass/0")
{
	uint8_t ip[16] =
			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xFF, 0xFF, 192, 168, 0, 0 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 127,
		.ip =
			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xFF, 0xFF, 192, 168, 0, 0 } };

	subnet_check((uint8_t*) &ip, &subnet);

	// .1 should be in the subnet .1, nothing should be changed
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_check/ipv4/pass/1")
{
	uint8_t ip[16] =
			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xFF, 0xFF, 192, 168, 1, 0 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 119,
		.ip =
			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xFF, 0xFF, 192, 168, 0, 0 } };

	subnet_check((uint8_t*) &ip, &subnet);

	// .1 should be in the subnet .1, nothing should be changed
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_check/ipv4/fail/0")
{
	uint8_t ip[16] =
			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xFF, 0xFF, 192, 168, 0, 0 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 97,
		.ip =
			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xFF, 0xFF, 10, 20, 0, 0 } };

	subnet_check((uint8_t*) &ip, &subnet);

	// 192 does not match 10, the entire ip should get zerod
	return is_zeros(ip, sizeof(ip));
}

TQ_TEST("subnet_check/ipv4/fail/1")
{
	uint8_t ip[16] =
			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xFF, 0xFF, 192, 168, 0, 1 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 128,
		.ip =
			{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0xFF, 0xFF, 192, 168, 0, 0 } };

	subnet_check((uint8_t*) &ip, &subnet);

	// .0 is not in .1, the entire ip should get zerod
	// (only the masked area gets checked)
	return is_zeros(ip, sizeof(ip));
}
