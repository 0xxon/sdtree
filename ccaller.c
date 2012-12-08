


#include <stdio.h>
#include "sdtree.h"

int main (int argc, char *argv[]) {
	void* fp = fpublish_create();
	fpublish_printEcInformation(fp);

	char revoke[] = "10000000000000000000000000000000";
        tDPath p = StringToDoublePath(revoke);
        p |= 0x1LL << ((2* ( 32 - 31) )-1);
        fpublish_revokeuser(fp, p);


	fString data = fpublish_getServerData(fp);
	fpublish_writeServerData(fp, "testdata");
	printf("Length: %u\n\n", data.length);

	char revoke2[] = "00000000000000000000000000000001";
	tPath p2 = StringToPath(revoke2);
        fpublish_generateKeylist(fp, p2);

	//printf("%s\n\n\n", data.data);
	return 0;
}
