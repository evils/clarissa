#include <libtq/test.h>
#include "../clarissa.h"
#include "../clarissa_internal.h"

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

TQ_TEST("subnet_filter/ipv6/pass0")
{
	uint8_t ip[16] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 0,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

	// ::1/127 should be in the subnet ::1/127
	// nothing should be changed
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv6/pass1")
{
	uint8_t ip[16] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 0,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

	// ::1/127 should be in the subnet ::1/127
	// nothing should be changed
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv6/fail0")
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

	// ::1/127 should not be in ::2/127, (0b01, ob10)
	// CAUTION! currently don't have an a way to obtain an
	// IPv6 subnet, hence only filtering out multicast
	return !memcmp(&ip, &start, sizeof(ip));
}

TQ_TEST("subnet_filter/ipv6/fail1")
{
	uint8_t ip[16] =
		{ 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	uint8_t start[16];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 0,
		.ip =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } };

	subnet_filter((uint8_t*) &ip, &subnet, true);

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

TQ_TEST("subnet_filter/ipv4/pass/0")
{
	uint8_t ip[4] = { 192, 168, 0, 0 };
	uint8_t start[4];
	memcpy(&start, &ip, sizeof(ip));

	struct Subnet subnet = { .mask = 127,
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
	char* intent = "0.0.0.0";
	int ret = !strncmp(ip_string, intent, INET6_ADDRSTRLEN);
	free(ip_string);
	return ret;
}

TQ_TEST("asprint_mac")
{
	uint8_t mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	char* mac_string;
	asprint_mac(&mac_string, mac);
	char* intent = "ff:ff:ff:ff:ff:ff";
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

TQ_TEST("map_ipv4")
{
	uint8_t ipv6[16] = {0};
	uint8_t ipv4[4] = {192, 168, 1, 0};

	uint8_t intent[16] =
		{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0xFF, 0xFF, 192, 168, 1, 0 };

	map_ipv4(ipv6, ipv4);

	return (!memcmp(ipv6, intent, 16));
}

TQ_TEST("addrss_valid")
{
	// all zero, invalid
	struct Addrss addrss = {0};
	// non-zero MAC and timeval, valid
	struct Addrss bddrss = {
			.mac = { 0, 0, 0, 0, 0, 1 },
			.ipv4_t.tv_sec = 1
		};

	// either zero, invalid
	struct Addrss cddrss = {
			.mac = { 0, 0, 0, 0, 0, 1 },
			.ipv4_t.tv_sec = 0
		};
	struct Addrss dddrss = {
			.mac = { 0, 0, 0, 0, 0, 0 },
			.ipv4_t.tv_sec = 1
		};

	// non-zero MAC and IPv4_t should be valid
	return !addrss_valid(&addrss)
	    &&  addrss_valid(&bddrss)
	    && !addrss_valid(&cddrss)
	    && !addrss_valid(&dddrss);
}

/*
TQ_TEST("addrss_list_nag")
{
	// this may need to get refactored to be easily testable
	return 1;
}

TQ_TEST("get_addrss")
{
	this'll take some work, just run the thing...
	return 1;
}
*/
