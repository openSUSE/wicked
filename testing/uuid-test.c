#include <stdio.h>
#include <wicked/util.h>

int main(void)
{
	ni_uuid_t uuid;
	char *string;
	int rv = 0;

	memset(&uuid, 0, sizeof(uuid));

	string = "aabbccddeeffAABBCCDDEEFF00112233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aabbccddeeffAABBCCDDEEFF00112233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aabbccddeeffAABBCCDDEEFF00112233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aabbRcdd-eeff-AABB-CCDD-EEFF00112233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aabbccdd-eeff-AABB-CCDD-EEFF00112233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aabbccdd-eeffAABB-CCDDEEFF-00112233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aa-bb-cc-dd-ee-ff-AA-BB-CC-DD-EE-FF-00-11-22-33";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aabb-ccdd-eeff-AABB-CCDD-EEFF-0011-2233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aabb-ccdd-eeff-AABB-CCDD-EEFF-0011-2233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aabb-ccdd-eeff-AABB-CCDD-EEFF-0011-2233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aabb-ccdd-eeff-AABB-CCDD-EEFF-0011-2233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	string = "aabbccddeeffAABB-CCDDEEFF00112233";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));


	string = "aabb-ccdd-eeff-AABB-CCDD-EEFF";
	rv = ni_uuid_parse(&uuid, string);
	printf("\nString\t\t=%s\n", string);
	printf("UUID\t\t=%s\n", ni_uuid_print(&uuid));
	printf("$? = %d\n", rv);
	memset(&uuid, 0, sizeof(uuid));

	return 0;
}
