#include <stdio.h>
#include <wicked/xml.h>
#include <wicked/util.h>

int main(void)
{
	xml_node_t *node;
	ni_uuid_t nsid;
	ni_uuid_t uuid;
	char *string;
	int rv = 0;

	ni_uuid_parse(&nsid, "c89756cc-b7fb-569b-b7f0-49a400fa41fe");
	printf("Namespace UUID: %s\n", ni_uuid_print(&nsid));

	/*
	 * -> UUIDv3: 52c17385-3d17-303b-af7b-c8f0302bbb51
	 * -> UUIDv5: 25fb0f02-0f8d-539a-800f-5b33243fd70b
	 */
	node = xml_node_new("interface", NULL);
	xml_node_new_element("name", node, "lo");
	xml_node_new("link", node);
	printf("XML node data:\n");
	xml_node_print(node, stdout);

	if (xml_node_uuid(node, 3, &nsid, &uuid))
		printf("Can't generate xml node uuid v3\n");
	else
		printf("XML node UUIDv3: %s\n", ni_uuid_print(&uuid));

	if (xml_node_uuid(node, 5, &nsid, &uuid))
		printf("Can't generate xml node uuid v5\n");
	else
		printf("XML node UUIDv5: %s\n", ni_uuid_print(&uuid));

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
