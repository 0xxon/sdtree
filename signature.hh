// stuff for the Elliptic Curve signature, that is used in the subset difference tree
//
// Johanna Amann <johanna@0xxon.net>

#ifndef SIGNATURE_HH
#define SIGNATURE_HH

// define the name of the EC-Curve that we use for all our operations
#define ECCURVENAME NID_secp384r1

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <string>
#include <assert.h>
#include <iostream>
#include <stdint.h>

/**
 * this class contains an Eliptic Curve signature and (public or private) key
 */
class cSignature {
private:
	ECDSA_SIG *ecsig;
	EC_KEY	*eckey;
	bool mHavePrivateKey;
	bool mHavePublicKey;
	bool mHaveSignedData;
public:
	cSignature();
	~cSignature();
	cSignature(const cSignature &);
	cSignature& operator=(const cSignature&);
	void SetPrivateKey(const unsigned char** key, uint32_t keylen);
	void SetPublicKey(const unsigned char** key, uint32_t keylen);
	void SetPublicKey(const std::string &mNewSig);
	void PrintECInformation() const;
	void SignSHA1Hash(const unsigned char *hash);
	int GetPublicKeyLength() const;
	int GetPrivateKeyLength() const;
	void GetPrivateKey(unsigned char **pkey);
	std::string GetPublicKey() const;
	std::string GetPrivateKey() const;
	std::string GetSignature() const;
	void SetSignature(const unsigned char **pp, uint32_t l);
	void SetSignature(const std::string &);
	int VerifySHA1Hash(const unsigned char *hash) const;
	std::string ExportSignature() const;
	void ImportSignature(const std::string &);

};

#endif /* SIGNATURE_HH */

/** @} */
