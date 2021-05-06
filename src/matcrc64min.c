/* Simple CRC64 utility.
 *
 * Copyright (c) 2020 Mattis Michel <sic_zer0@hotmail.com>
 *
 * Polynomial used is 0x42f0e1eba9ea3693 (ECMA-182).
 * Input and result are reflected.
 * Initial value is 0xffffffffffffffff.
 */

#include <stdint.h>
#include <stdio.h>

#define BUFSZ 4096

uint64_t crc64(uint64_t crc, const void *data, size_t len) {
	uint8_t *ptr = (uint8_t *) data, *end = ptr + len;
	int i;
	while (ptr < end) {
		crc ^= *ptr++;
		for (i = 0; i < 8; ++i)
			crc = (crc >> 1) ^ (-(crc & 1) & 0xc96c5795d7870f42);
	}
	return crc;
}

int main() {
	static char *buf[BUFSZ];
	size_t len;
	uint64_t crc = 0xffffffffffffffff;

	while (!feof(stdin)) {
		len = fread(buf, 1, sizeof(buf), stdin);
		crc = crc64(crc, buf, len);
		if (ferror(stdin)) {
			fprintf(stderr, "Failure while reading stdin.\n");
			return 1;
		}
	}

	printf("%016llx\n", (unsigned long long) crc);

	return 0;
}
