// Implementation file for the C compatibility layer of the subset difference algorithm library
//
// Johanna Amann <johanna@0xxon.net>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <iostream>
#include <sstream>
#include <string.h>

#include "sdtree.h"
#include "fpublish.hh"
#include "fclient.hh"
#include "sdtcommon.hh"

using std::string;
using std::istringstream;
using std::ostringstream;

fString string_to_fString(string data) {
	fString out;
	out.length = data.length();
	char * outdata = (char*) malloc(out.length);
	memcpy(outdata, data.data(), out.length);
	out.data = outdata;
	return out;
}

void * fpublish_create() {
	cFPublish* fs;
	fs = new cFPublish();
	return (void*) fs;
}

void * fpublish_create_from_file(char * filename) {
	cFPublish* fs;
	string file = string(filename);
	fs = new cFPublish(file);
	return (void*) fs;
}

void* fpublish_create_from_data(char * data, size_t size) {
	cFPublish* fs;
	string s = string(data, size);
	istringstream instream;
	instream.str(s);
	fs = new cFPublish(instream);
	return (void*) fs;
}

void fpublish_clearRevokedUsers(void* object) {
	cFPublish* fs = (cFPublish*) object;
	fs->ClearRevokedUsers();
}

void fpublish_printEcInformation(void * object) {
	cFPublish* fs = (cFPublish*) object;
	fs->PrintECInformation();
}

void fpublish_generateCover(void * object) {
	cFPublish* fs = (cFPublish*) object;
	fs->GenerateCover();
}

void fpublish_printSDKeyList(void * object) {
	cFPublish* fs = (cFPublish*) object;
	fs->PrintSDKeyList();
}

void fpublish_setTreeSecret(void * object, char * secret, size_t length) {
	cFPublish* fs = (cFPublish*) object;
	string data = string(secret, length);

	fs->SetTreeSecret(data);
}

fString fpublish_generateSDTreeBlock(void * object, char * data, size_t length) {
	cFPublish* fs = (cFPublish*) object;
	string enc = string(data, length);

	string out = fs->GenerateSDTreeBlock(enc);
	fString realout = string_to_fString(out);
	return realout;
}

fString fpublish_generateAESEncryptedBlock(void * object, char * data, size_t length) {
	cFPublish* fs = (cFPublish*) object;
	string enc = string(data, length);
	
	string out = fs->GenerateAESEncryptedBlock(enc);
	fString realout = string_to_fString(out);
	return realout;
}

void fpublish_writeClientData(void * object, char * filename) {
	cFPublish* fs = (cFPublish*) object;
	string fn = string(filename);
	
	fs->WriteClientData(fn);
}
	
void fpublish_writeServerData(void * object, char * serverfile) {
	cFPublish* fs = (cFPublish*) object;
	string fn = string(serverfile);
	
	fs->WriteServerData(fn);
	
}

fString fpublish_getClientData(void * object) {
	cFPublish* fs = (cFPublish*) object;
	ostringstream oss;
	fs->WriteClientData(oss);
	string str = oss.str();
	fString out = string_to_fString(str);
	return out;
}

fString fpublish_getServerData(void * object) {
	cFPublish* fs = (cFPublish*) object;
	ostringstream oss;
	fs->WriteServerData(oss);
	string str = oss.str();
	fString out = string_to_fString(str);
	return out;
}

void fpublish_revokeuser(void * object, const tDPath rPath) {
	cFPublish* fs = (cFPublish*) object;
	fs->RevokeUser(rPath);
}
	
void fpublish_generateKeylist(void * object, const tPath path) {
	cFPublish* fs = (cFPublish*) object;
	fs->generate_keylist(path);
}

void fpublish_free(void* object) {
	cFPublish* fs = (cFPublish*) object;
	delete fs;
}


unsigned int fpublish_getRevokelistInverted(void * object) {
	cFPublish* fs = (cFPublish*) object;
	if ( fs->GetRevokelistInverted() ) {
		return 1;
	} else {
		return 0;
	}
}


void fpublish_setRevokelistInverted(void* object, const unsigned int set) {
	cFPublish* fs = (cFPublish*) object;
	if ( set > 0 ) {
		fs->SetRevokelistInverted(true);
	} else {
		fs->SetRevokelistInverted(false);
	}
}


void* fclient_create(char * filename) {
	string fn = string(filename);
	cFClient* fc = new cFClient(fn);
	return (void*) fc;
}

void* fclient_create_from_data(char * data, size_t size) {
	string s = string(data, size);
	cFClient* fc;
	istringstream instream;
	instream.str(s);
	fc = new cFClient(instream);
	return (void*) fc;
}	
	
	
fString fclient_decrypt(char* object, char * data, size_t length) {
	cFClient* fc = (cFClient*) object;
	string decrypt = string(data, length);
	try {
		string out = fc->Decrypt(decrypt);
		fString realout = string_to_fString(out);
		return realout;
	} catch ( cSDTreeCommon::ClientException c ) {
		fString s;
		s.length = 0;
		s.data = 0;
		return s;
	}

}	
	
void fclient_free(char * object) {
	cFClient* fc = (cFClient*) object;
	delete fc;
}

tPath DoublePathToPath(tDPath path) {
	return cSDTreeCommon::DoublePathToPath(path);
}

int GetLayer(tDPath path) {
	return cSDTreeCommon::GetLayer(path);
}

tPath StringToPath(const char * in) {
	string p = string(in);
	return cSDTreeCommon::StringToPath(p);
}

tDPath StringToDoublePath(const char * in) {
	string p = string(in);
	return cSDTreeCommon::StringToDoublePath(p);
}

char * DoublePathToString(const tDPath path) {
	string r = cSDTreeCommon::DoublePathToString(path);
	char * out = (char*) malloc(r.length()+1);
	strcpy(out, r.c_str());
	return out;
}

char * PathToString(const tPath path) {
	string r = cSDTreeCommon::PathToString(path);
	char * out = (char*) malloc(r.length()+1);
	strcpy(out, r.c_str());
	return out;
}
