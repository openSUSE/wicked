#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <wicked/util.h>

int main(int argc, char *argv[])
{
	unsigned char bin[80];
	char str[sizeof(bin)*3], *sep = "";
	size_t slen, blen, l;
	int n, len;

	for (n = 1; n < argc && argv[n]; ++n) {

		if (!strcmp(argv[n], "-s")) {
			sep = argv[++n];
			printf("SEP: %s\n", sep);
			continue;
		}

		printf("ARG[%d](%zu): %s\n", n, strlen(argv[n]), argv[n]);

		slen = strlen(argv[n]);
		if ((slen * 3) >= sizeof(bin)) {
			fprintf(stderr, "ERR: cannot handle input -- too long\n");
			continue;
		}

		memset(bin, 0, sizeof(bin));
		if ((len = ni_parse_hex_data(argv[n], bin, sizeof(bin), sep)) <= 0) {
			fprintf(stderr, "ERR: cannot parse hex input\n");
			continue;
		}
		blen = len;

		printf("BIN[%d](%zu):", n, blen);
		for (l = 0; l < blen; ++l) {
			printf(" 0x%02x", (unsigned int)bin[l] & 0xff);
		}
		printf("\n");

		if (ni_format_hex_data(bin, blen, str, sizeof(str), "", FALSE) > 0) {
			fprintf(stderr, "ERR: cannot format hex data\n");
			continue;
		}
		printf("H00[%d](%zu): %s\n", n, strlen(str), str);

		if (ni_format_hex_data(bin, blen, str, sizeof(str), ":", FALSE) > 0) {
			fprintf(stderr, "ERR: cannot format hex data\n");
			continue;
		}
		printf("H01[%d](%zu): %s\n", n, strlen(str), str);

		if (ni_format_hex_data(bin, blen, str, sizeof(str), "--", FALSE) > 0) {
			fprintf(stderr, "ERR: cannot format hex data\n");
			continue;
		}
		printf("H02[%d](%zu): %s\n", n, strlen(str), str);

		printf("\n");
	}
	return 0;
}
