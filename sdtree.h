// Header file for the C compatibility layer of the subset difference algorithm library
//
// Johanna Amann <johanna@0xxon.net>
// 

#ifndef _SDTREE_H_
#define _SDTREE_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#ifndef SDTCOMMON_HH_
typedef uint32_t tPath;
typedef uint64_t tDPath;
#endif

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct  {
		size_t length;
		char * data;
	} fString;

	/* fpublish */
	void* fpublish_create();
	void* fpublish_create_from_file(char * filename);
	void* fpublish_create_from_data(char * data, size_t size);
	void fpublish_printEcInformation(void * object);
	void fpublish_generateCover(void * object);
	void fpublish_printSDKeyList(void * object);
	void fpublish_setTreeSecret(void * object, char * secret, size_t length);
	fString fpublish_generateSDTreeBlock(void * object, char * data, size_t length);
	fString fpublish_generateAESEncryptedBlock(void * object, char * data, size_t length);
	void fpublish_revokeuser(void * object, const tDPath rPath); 
	void fpublish_generateKeylist(void * object, const tPath path);
	void fpublish_writeClientData(void * object, char * filename);
	void fpublish_writeServerData(void * object, char * serverfile);
	fString fpublish_getClientData(void * object);
	fString fpublish_getServerData(void * object);
	void fpublish_free(void * object);
	unsigned int fpublish_getRevokelistInverted(void * object);
	void fpublish_setRevokelistInverted(void* object, const unsigned int);
	void fpublish_clearRevokedUsers(void* object);
	
	/* fclient */
	void* fclient_create(char * filename);
	void* fclient_create_from_data(char * data, size_t size);
	fString fclient_decrypt(char* object, char * data, size_t length);
	void fclient_free(char * object);
	
	/* important stuff from sdtcommon */
	tPath DoublePathToPath(tDPath path);
	int GetLayer(tDPath path);
	tPath StringToPath(const char * in);
	tDPath StringToDoublePath(const char * in);
	char * DoublePathToString(const tDPath path);
	char * PathToString(const tPath path);
	
	
#ifdef __cplusplus
}
#endif

#endif /* _SDTREE_H_ */

