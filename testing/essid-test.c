/*
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <wicked/wireless.h>
#include <wicked/util.h>
#include "util_priv.h"

static const char bin_ssid1[] = {
	' ', ' ', '\\', 'p', 'o', 'w', 'e', 'r', '/', ' ', ' ', '\0'
};
static const char bin_ssid2[] = {
	'\\', 'x', '0', '-', '-', 'h', 'i', 'd', 'd', 'e', 'n', '-', '-', '\\', 'x', '4', '0', '\0'
};
static const char *test1_essid[] = {
	bin_ssid1,
	bin_ssid2,
	"  \\power/  ",
	"  \\route66/  ",
	"G\xe4stenetzwerk",
	"//{}[],;&%\r\n\007\t\e\x01\x02\x03\xaa\xfe\xee\\\\x\xff",
	NULL,
};

void
ssid_parse(const char *string, ni_wireless_ssid_t *ssid)
{
	const char *escaped;
	const char *hex_str;
	size_t len;
	char *hex;
	ni_stringbuf_t buf = NI_STRINGBUF_INIT_DYNAMIC;

	len = ni_string_len(string);
	hex = ni_sprint_hex((const unsigned char *)string, len);

	if (ni_wireless_ssid_parse(ssid, string)) {
		escaped = ni_wireless_ssid_print(ssid, &buf);
		hex_str = ni_print_hex(ssid->data, ssid->len);

		printf("ESSID(hex):\t'%s'", hex);
		printf("\n\t=> esc:\t'%s'", escaped);
		printf("\n\t=> hex:\t'%s'", hex_str);
	} else {
		printf("ESSID(hex):\t'%s'", hex);
		printf("\tcannot be parsed");
	}
	printf("\n\n");
	ni_string_free(&hex);
	ni_stringbuf_destroy(&buf);
}

int
main(int argc, char **argv)
{
	ni_wireless_ssid_t ssid;
	int n;

	if (argc == 1) {
		for (n = 0; test1_essid[n]; ++n) {
			ssid_parse(test1_essid[n], &ssid);
		}
	} else {
		for (n = 1; n < argc && argv[n]; ++n) {
			ssid_parse(argv[n], &ssid);
		}
	}

	return 0;
}

