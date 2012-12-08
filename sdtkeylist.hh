// stuff for the SD-publisher and client
// 
// Johanna Amann <johanna@0xxon.net>

#ifndef SDTKEYLIST_HH
#define SDTKEYLIST_HH

#include "sdtcommon.hh"
#include "signature.hh"
#include <string>

/**
 * Class that mainly implements the Keylist stuff that is used by both the
 * clients and publishers that use the Subset Difference Revocation
 * Algorithm
 */
class cSDTreeKeyList {
private:
	void InitKeyList();
protected:
	uint32_t mFsRev;	///< file system revision
	cSDTreeCommon::keyEntry *keylist;
	int num_keys;
	cSignature *mSig;
	tPath ourPath;
public:
	cSDTreeKeyList();
	virtual ~cSDTreeKeyList();
	void PrintECInformation() const;
	void PrintKeylist() const;
	cSignature SignData(const std::string &) const;
	cSignature SignHash(const std::string &) const;
	cSignature GetSignature() const;
	uint32_t GetMajorRevision() const;
};

#endif /* SDTKEYLIST_HH */

/** @} */
