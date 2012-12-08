// For server:
// filesystem publisher block creation and manipulation class
//
// Johanna Amann <johanna@0xxon.net>


#ifndef FPUBLISH_HH
#define FPUBLISH_HH

#include <string>
#include <set>
#include <vector>

#include "sdtcommon.hh"
#include "signature.hh"
#include "sdtkeylist.hh"

/**
 * Class for the publishing of a Subset Difference Tree. Allows Key generation, Revocation
 * and enryption of data
 */
class cFPublish : public cSDTreeKeyList
{
private:
	void LoadServerData(std::istream &stream);
	void GetMasterKey(const tPath spath, const uint32_t depth, unsigned char *key) const;
	void GetKey(const tPath path, const unsigned int subset, const unsigned int difference, unsigned char *key) const;
	void GetKey(cSDTreeCommon::keyEntry *entry) const;
	void GetCenterKey(cSDTreeCommon::keyEntry *entry) const;
	void InitAESMasterKey();
	void InitAESMasterKeyIv();

	unsigned char *aesmasterkey;
	unsigned char *aesmasterkeyiv;
	bool revokelistInverted; ///< is the revokelist inverted? if true, the revokelist contains the node that may decrypt, not the nodes that are revoked.
	bool revokelistInvertedInMemory; ///< the revokelist inversion was already done; the revokelist contains the nodes which may not decrypt.
	std::set<tDPath> revokelist;
	std::vector<cSDTreeCommon::keyEntry> sdkeylist; ///< the list that contains the actual keys that are used
	std::string mTreeSecret; ///< the secret that is used for our tree key generation
	std::set<tDPath> GetInvertedRevokelist();

public:
	cFPublish();
	cFPublish(std::istream &stream);
	cFPublish(std::string path);
	~cFPublish();
	void generate_keylist(const tPath path);
	void WriteClientData(std::ostream &stream);
	void WriteClientData(const std::string &path);
	void WriteServerData(std::ostream &stream);
	void WriteServerData(const std::string &path);
	void PrintSDKeyList();
	void RevokeUser(const tDPath rPath);
	void ClearRevokedUsers();
	void GenerateCover();
	void GenerateEncryptedCoverKeys(cSDTreeCommon::coverKey* coverKeyList);
	std::string GenerateSDTreeBlock(const std::string &message);
	std::string GenerateAESEncryptedBlock(const std::string &message) const;
	void SetTreeSecret(const std::string &);
	bool GetRevokelistInverted();
	void SetRevokelistInverted(const bool);
};


#endif // FPUBLISH_HH

/** @} */
