#define _GNU_SOURCE
#include <libtq/test.h>
#include "../src/clarissa.c"
#include "../src/clarissa.h"
#include "../src/clarissa_cat.c"
#include "../src/clarissa_cat.h"
#include "../src/clarissa_defines.h"

TQ_TEST("net_put_u16")
{
	// 0b1000000000000001
	uint16_t source = 32769;
	// 0b0000000110000000
	uint16_t intent = 384;
	uint8_t target[2];

	net_put_u16((uint8_t*) target, source);

	return !memcmp(target, &intent, sizeof(target));
}

TQ_TEST("net_get_u16")
{
	uint8_t source[2] = {0};
	net_put_u16(source, 384);
	if (net_get_u16(source) == 384) return 1;
	return 0;
}

TQ_TEST("net_put_u32")
{
	// 0b10000000000000011000000000000001
	uint32_t source = 2147581953;
	// 0b00000001100000000000000110000000
	uint32_t intent = 25166208;
	uint8_t target[4];

	net_put_u32((uint8_t*) target, source);

	return !memcmp(target, &intent, sizeof(target));
}

TQ_TEST("net_get_u32")
{
	uint8_t source[4] = {0};
	net_put_u32(source, 25166208);
	if (net_get_u32(source) == 25166208) return 1;
	return 0;
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

TQ_TEST("subnet_filter/ipv6/pass/0")
{
	uint8_t ip[16] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 128,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

	// ::1 should match with ::1/128
	// nothing should be changed
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv6/pass/1")
{
	uint8_t ip[16] =
		{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 1,
		.ip =
		{ 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

	// 80::1 should match with 81::/1
	// nothing should be changed
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv6/fail/0")
{
	uint8_t ip[16] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 127,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

	// ::1 should not match with ::2/127, (0b01, ob10)
	return is_zeros(ip, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv6/fail/1")
{
	uint8_t ip[16] =
		{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 2,
		.ip =
		{ 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

	// ip 0b10000000 is not in subnet 0b11000000 and should be zerod
	return is_zeros(ip, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv6_mapped/pass")
{
	uint8_t ip[16] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 192, 168, 1, 0 };

	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 127,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 192, 168, 1, 0 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

	// .0 should be in .0, nothing should change
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv6_mapped/fail")
{
	uint8_t ip[16] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 192, 168, 1, 0 };

	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 128,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 192, 168, 1, 1 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

	// .0 should not be in .1, ip should be zerod
	return is_zeros(ip, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv6_multicast/0")
{
	uint8_t ip[16] =
		{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

	// subnet should be ignored (0xff is a special case)
	struct Subnet subnet = { .mask = 0,
		.ip =
		{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

	// IPs starting with 0xff are multicast
	// multicast addresses should be zeroed
	return is_zeros(ip, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv6_multicast/1")
{
	uint8_t ip[16] =
		{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

	// subnet should be ignored (0xff is a special case)
	struct Subnet subnet = { .mask = 128,
		.ip =
		{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

	// IPs starting with 0xff are multicast
	// multicast addresses should be zeroed
	return is_zeros(ip, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv4_multicast/0")
{
	uint8_t ip[4] = { 255, 168, 0, 0 };

	// subnet should be ignored (255.* is a special case)
	struct Subnet subnet = { .mask = 0,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 255, 168, 0, 0 } };

	subnet_filter((uint8_t*) &ip, &subnet, false);

	// IPs starting with 0xff are multicast
	// multicast addresses should be zeroed
	return is_zeros(ip, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv4_multicast/1")
{
	uint8_t ip[4] = { 255, 168, 0, 0 };

	// subnet should be ignored (255.* is a special case)
	struct Subnet subnet = { .mask = 128,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 255, 168, 0, 0 } };

	subnet_filter((uint8_t*) &ip, &subnet, false);

	// IPs starting with 0xff are multicast
	// multicast addresses should be zeroed
	return is_zeros(ip, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv4/pass/0")
{
	uint8_t ip[4] = { 192, 168, 0, 0 };
	uint8_t start[4];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 128,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 192, 168, 0, 0 } };

	subnet_filter((uint8_t*) &ip, &subnet, false);

	// .1 should be in the subnet .1, nothing should be changed
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv4/pass/1")
{
	uint8_t ip[4] = { 192, 168, 1, 0 };
	uint8_t start[4];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 119,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 192, 168, 0, 0 } };

	subnet_filter((uint8_t*) &ip, &subnet, false);

	// .1 should be in the subnet .1, nothing should be changed
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv4/fail/0")
{
	uint8_t ip[4] = { 192, 168, 0, 0 };
	uint8_t start[4];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 97,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 10, 20, 0, 0 } };

	subnet_filter((uint8_t*) &ip, &subnet, false);

	// 192 does not match 10, the entire ip should get zerod
	return is_zeros(ip, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv4/fail/1")
{
	uint8_t ip[4] = { 192, 168, 0, 1 };
	uint8_t start[4];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 128,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 192, 168, 0, 0 } };

	subnet_filter((uint8_t*) &ip, &subnet, false);

	// .0 is not in .1, the entire ip should get zerod
	// (only the masked area gets checked)
	return is_zeros(ip, sizeof(ip));
}

TQ_TEST("asprint_ip/ipv4")
{
	uint8_t ip[4] = { 192, 168, 0, 1 };
	char* ip_string;
	// bool indicates if this is an IPv6 address
	asprint_ip(&ip_string, ip, false);
	char* intent = "192.168.0.1";
	int ret = !strcmp(ip_string, intent);
	free(ip_string);

	return ret;
}

TQ_TEST("asprint_ip/ipv4_null")
{
	uint8_t ip[4] = { 0, 0, 0, 0 };
	char* ip_string;
	asprint_ip(&ip_string, ip, false);
	char* intent = "0.0.0.0";
	int ret = !strcmp(ip_string, intent);
	free(ip_string);
	return ret;
}

TQ_TEST("asprint_ip/ipv6_null")
{
	uint8_t ip[16] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	char* ip_string;
	asprint_ip(&ip_string, ip, true);
	char* intent = "::";
	int ret = !strncmp(ip_string, intent, INET6_ADDRSTRLEN);
	free(ip_string);
	return ret;
}

TQ_TEST("asprint_ip/ipv6_full")
{
	uint8_t ip[16] =
		{ 0x20, 0x01, 0x0D, 0xB8, 0x11, 0x11, 0x11, 0x11,
		  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x27 };
	char* ip_string;
	asprint_ip(&ip_string, ip, true);
	// want max size
	char* intent = "2001:db8:1111:1111:1111:1111:1111:1127";
	int ret = !strncmp(ip_string, intent, INET6_ADDRSTRLEN);
	free(ip_string);
	return ret;
}

TQ_TEST("asprint_ip/ipv6_short")
{
	uint8_t ip[16] =
		{ 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27 };
	char* ip_string;
	asprint_ip(&ip_string, ip, true);
	// want max size
	char* intent = "2001:db8::27";
	int ret = !strncmp(ip_string, intent, INET6_ADDRSTRLEN);
	free(ip_string);
	return ret;
}

TQ_TEST("asprint_ip/ipv6_short_gap")
{
	uint8_t ip[16] =
		{ 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27 };
	char* ip_string;
	asprint_ip(&ip_string, ip, true);
	// want max size
	char* intent = "2001:db8::1:0:0:27";
	int ret = !strncmp(ip_string, intent, INET6_ADDRSTRLEN);
	free(ip_string);
	return ret;
}

TQ_TEST("asprint_ip/ipv6_mapped_ipv4_null")
{
	uint8_t ip[16] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 };
	char* ip_string;
	asprint_ip(&ip_string, ip, true);
	char* intent = "::ffff:0.0.0.0";
	int ret = !strncmp(ip_string, intent, INET6_ADDRSTRLEN);
	free(ip_string);
	return ret;
}

TQ_TEST("asprint_mac")
{
	uint8_t mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	char* mac_string;
	asprint_mac(&mac_string, mac);
	char* intent = "FF:FF:FF:FF:FF:FF";
	int ret = !strncmp(mac_string, intent, 18);
	free(mac_string);
	return ret;
}

TQ_TEST("get_cidr")
{
	char cidr[] = "192.168.0.0/16";
	struct Subnet dest;
	uint8_t ip_intent[16] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 192, 168, 0, 0 };
	if (get_cidr(&dest, cidr)
		&& !bitcmp(ip_intent, dest.ip, 16 * 8)
		&& dest.mask == 16 + 96)
	{
		return 1;
	}
	return 0;
}

TQ_TEST("addrss_list_add/new")
{
	struct Addrss* head = NULL;
	struct Addrss two;
	struct Addrss one;
	memset(&two, 0, sizeof(two));
	memset(&one, 0, sizeof(one));
	two.mac[5] = 2;
	one.mac[5] = 1;
	addrss_list_add(&head, &two);
	addrss_list_add(&head, &one);

	uint8_t test = head->next->mac[5];

	for (struct Addrss* tmp; head != NULL;)
        {
                tmp = head;
                head = head->next;
                free(tmp);
        }

	if (test == 2)
	{
		return 1;
	}
	return 0;
}

TQ_TEST("addrss_list_add/same")
{
	struct Addrss* head = NULL;
	struct Addrss one;
	memset(&one, 0, sizeof(one));
	one.mac[5] = 1;
	addrss_list_add(&head, &one);
	addrss_list_add(&head, &one);

	int test = 0;
	if (head->next == NULL) test++;

	for (struct Addrss* tmp; head != NULL;)
        {
                tmp = head;
                head = head->next;
                free(tmp);
        }

	if (test)
	{
		return 1;
	}
	return 0;
}

TQ_TEST("addrss_list_cull")
{
	struct Addrss* head = NULL;
	struct Addrss two, one;
	struct timeval earlier, now;
	// 10s timeout
	int timeout = 10000;
	int nags = 3;
	memset(&two, 0, sizeof(two));
	memset(&one, 0, sizeof(one));
	memset(&now, 0, sizeof(now));
	memset(&earlier, 0, sizeof(earlier));

	// can't set earlier to less than 0
	// so set "now" to more than timeout
	now.tv_sec = timeout + 1;
	two.mac[5] = 2;
	two.ipv4_t = now;
	one.mac[5] = 1;
	one.ipv4_t = earlier;
	one.tried = nags;

	addrss_list_add(&head, &two);
	addrss_list_add(&head, &one);

	addrss_list_cull(&head, &now, timeout, nags);

	int cull_success = 0;
	if (head->next == NULL && head->mac[5] == 2)
	{
		cull_success = 1;
	}

	for (struct Addrss* tmp; head != NULL;)
        {
                tmp = head;
                head = head->next;
                free(tmp);
        }

	if (cull_success)
	{
		return 1;
	}
	return 0;
}

TQ_TEST("addrss_valid")
{
	// an all zero MAC address is the best indication of a bad extraction
	// an all zero timestamp may also be a fair indication
	// but i'm not sure that couldn't occur in synthetic pcap files
	// and with a zero timestamp an entry will get culled within a timeout * nags
	struct Addrss addrss = {
			.mac = { 0, 0, 0, 0, 0, 0 },
		};
	struct Addrss bddrss = {
			.mac = { 0, 0, 0, 0, 0, 1 },
		};

	// non-zero MAC addresses should be valid
	return !addrss_valid(&addrss) && addrss_valid(&bddrss);
}

TQ_TEST("asprint_clar/pass/simple")
{
	struct Addrss addrss = {
			.mac = { 0, 0, 0, 0, 0, 1 },
			.ts.tv_sec = 1582928932,
			.ipv4 = { 10, 20, 0, 1 },
			.ipv4_t.tv_sec = 1581412781,
			.ipv6 = { 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00
				, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
				, 0x00, 0x27 },
			.ipv6_t.tv_sec = 1581412782
		};
	char* intent =
"00:00:00:00:00:01   1582928932   10.20.0.1         1581412781   2001:db8::27                              1581412782\n";
	char* result;
	asprint_clar(&result, &addrss);
	int diff = strncmp(intent, result, strlen(intent));
	free(result);
	return !diff;
}

TQ_TEST("asprint_clar/pass/zero_IPv4")
{
	struct Addrss addrss = {
			.mac = { 0, 0, 0, 0, 0, 1 },
			.ts.tv_sec = 1582928932,
			.ipv4 = { 0, 0, 0, 0 },
			.ipv4_t.tv_sec = 0,
			.ipv6 = { 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00
				, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
				, 0x00, 0x27 },
			.ipv6_t.tv_sec = 1581412782
		};
	char* intent =
"00:00:00:00:00:01   1582928932   0.0.0.0           0            2001:db8::27                              1581412782\n";
	char* result;
	asprint_clar(&result, &addrss);
	int diff = strncmp(intent, result, strlen(intent));
	free(result);
	return !diff;
}

TQ_TEST("asprint_clar/pass/max_IPv4_width")
{
	struct Addrss addrss = {
			.mac = { 0, 0, 0, 0, 0, 1 },
			.ts.tv_sec = 1582928932,
			.ipv4 = { 192, 168, 255, 255 },
			.ipv4_t.tv_sec = 1581412781,
			.ipv6 = { 0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00
				, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
				, 0x00, 0x27 },
			.ipv6_t.tv_sec = 1581412782
		};
	char* intent =
"00:00:00:00:00:01   1582928932   192.168.255.255   1581412781   2001:db8::27                              1581412782\n";
	char* result;
	asprint_clar(&result, &addrss);
	int diff = strncmp(intent, result, strlen(intent));
	free(result);
	return !diff;
}

TQ_TEST("asprint_clar/pass/zero_IPv6")
{
	struct Addrss addrss = {
			.mac = { 0, 0, 0, 0, 0, 1 },
			.ts.tv_sec = 1582928932,
			.ipv4 = { 192, 168, 255, 255 },
			.ipv4_t.tv_sec = 1581412782,
			.ipv6 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
				, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
				, 0x00, 0x00 },
			.ipv6_t.tv_sec = 0
		};
	char* intent =
"00:00:00:00:00:01   1582928932   192.168.255.255   1581412782   ::                                        0\n";
	char* result;
	asprint_clar(&result, &addrss);
	int diff = strncmp(intent, result, strlen(intent));
	free(result);
	return !diff;
}

TQ_TEST("asprint_clar/pass/max_IPv6_width")
{
	struct Addrss addrss = {
			.mac = { 0xbe, 0x69, 0x27, 0xde, 0xc3, 0xbe },
			.ts.tv_sec = 1582924127,
			.ipv4 = { 192, 168, 242, 127 },
			.ipv4_t.tv_sec = 1582924125,
			.ipv6 = { 0xfd, 0xe8, 0x83, 0x38, 0xbc, 0x3a, 0xd6
				, 0x6a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
				, 0xff, 0xff },
			.ipv6_t.tv_sec = 1582924126
		};
	char* intent =
"be:69:27:de:c3:be   1582924127   192.168.242.127   1582924125   fde8:8338:bc3a:d66a:ffff:ffff:ffff:ffff   1582924126\n";
	char* result;
	asprint_clar(&result, &addrss);
	int diff = strncmp(intent, result, strlen(intent));
	free(result);
	return !diff;
}

TQ_TEST("asprint_clar/pass/mapped_IPv4")
{
	struct Addrss addrss = {
			.mac = { 0, 0, 0, 0, 0, 1 },
			.ts.tv_sec = 1582928932,
			.ipv4 = { 192, 168, 255, 255 },
			.ipv4_t.tv_sec = 1581412782,
			.ipv6 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
				, 0x00, 0x00, 0x00, 0xFF, 0xFF
				, 192, 168, 1, 0 },
			.ipv6_t.tv_sec = 1582923679
		};
	char* intent =
"00:00:00:00:00:01   1582928932   192.168.255.255   1581412782   ::ffff:192.168.1.0                        1582923679\n";
	char* result;
	asprint_clar(&result, &addrss);
	int diff = strncmp(intent, result, strlen(intent));
	free(result);
	return !diff;
}

TQ_TEST("asprint_clar_header")
{
	char* result;
	// this should be manually updated as a barrier to accidental change
	char* intent = "#   clarissa   v1.0\n";
	asprint_clar_header(&result);
	int diff = strncmp(intent, result, strlen(intent));
	free(result);
	return !diff;
}

TQ_TEST("asprint_cat_header")
{
	char* result;
	char* intent =
"#   MAC_address       MAC_time     IPv4_address     IPv4_time                 IPv6_address                 IPv6_time\n";
	asprint_cat_header(&result);
	int diff = strncmp(intent, result, strlen(intent));
	free(result);
	return !diff;
}

/*
TQ_TEST("addrss_list_nag")
{
	// this may need to get refactored to be easily testable
	return 1;
}

TQ_TEST("get_addrss")
{
	// this'll take some work, just run the thing...
	return 1;
}
*/
