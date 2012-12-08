// For client:
// definition of filesystem location block decryption class
//
// Johanna Amann <johanna@0xxon.net>

#ifndef FCLIENT_HH
#define FCLIENT_HH

#include <string>

#include "signature.hh"
#include "sdtcommon.hh"
#include "sdtkeylist.hh"

/**
 * Class for a client that has to decrypt Subset Difference Tree data
 */
class cFClient : public cSDTreeKeyList {
private:
	void LoadClientData(std::istream &stream);
	void GetKey(const tPath path, const unsigned char* pathkey, const unsigned int begindepth, const unsigned int enddepth, unsigned char *key);
	void DecryptMasterKey(const unsigned int i, const unsigned char *key);
	std::string DecryptMessage();
	int FindTreeBlock();

	uint32_t* sdkeylist_size;
	cSDTreeCommon::nodeId* sdkeylist;
	unsigned char* message;
	uint32_t aesmessage_size;
	unsigned char* aesmessage;
	unsigned char* aesiv;
	cSDTreeCommon::coverKey* coverKeyList;
	unsigned char* masterkey;
	bool ParseSDTData(const std::string &data);
	bool ParseSData(const std::string &data);

public:
	cFClient(std::istream &stream);
	cFClient(const std::string &keyfile);
	~cFClient();
	std::string Decrypt(const std::string &data);
};

#endif /* FCLIENT_HH */

/** @} */
