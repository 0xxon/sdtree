// stuff for the Elliptic Curve signature, that is used in the subset difference tree
//
// Todo: perhaps the signature and the key itself should be moved in 2 different classes
// 
// Johanna Amann <johanna@0xxon.net>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#ifdef WIN32
#include <winsock2.h> /* ntoh hton */
#else
#include <arpa/inet.h> /* ntoh hton */
#endif
#include <cstring> /* for memcpy */

#include "signature.hh"

#define VERBOSE_ERRORS /* dump our error messages to cerr */

using namespace std;

/**
 * Default constructor
 */
cSignature::cSignature(): mHavePrivateKey(true), mHavePublicKey(true), mHaveSignedData(false) {
	ecsig = NULL;
	eckey = NULL;
	eckey = EC_KEY_new_by_curve_name(ECCURVENAME);
	assert(eckey != NULL);
	assert(EC_KEY_generate_key(eckey));
	// ok, now we should have got our elliptic curve key.
}

/**
 * copy-constructor
 *
 * \todo perhaps use openssl copy function
 */
cSignature::cSignature(const cSignature & rSig) : mHavePrivateKey(false), mHavePublicKey(false), mHaveSignedData(false) {
	ecsig = NULL;
	eckey = NULL;
	//eckey = EC_KEY_new_by_curve_name(ECCURVENAME);
	//assert(eckey != NULL);
	//cout << "Assigning signature" << endl;

	string key;

	// FIXME: there is a openssl copy function for keys; that would be much faster

	if ( rSig.mHavePrivateKey ) {
		key = rSig.GetPrivateKey();
		const unsigned char * keydata = reinterpret_cast<const unsigned char*>(key.data());
		SetPrivateKey(&keydata, key.length());
		mHavePrivateKey = true;
		mHavePublicKey = true;
	} else if ( rSig.mHavePublicKey) {
		key = rSig.GetPublicKey();
		const unsigned char * keydata = reinterpret_cast<const unsigned char*>(key.data());
		SetPublicKey(&keydata, key.length());
		mHavePublicKey = true;
	} else {
		// we have no key data
		assert(false);
	}


	// assert(eckey != NULL);

	if ( eckey == NULL ) {
		cout << "Attention, copied empty ec-key. If this is an unsigned reply to something this may be ok, but if signature errors schould occur later you know why" << endl;
	}

	if ( rSig.mHaveSignedData) {
		//cout << "Sig present" << endl;
		SetSignature(rSig.GetSignature());
	}
}

/**
 * assignment operator
 *
 * \todo perhaps use openssl copy function
 */
cSignature&
cSignature::operator=(const cSignature& rSig) {
	assert(this != &rSig); // that would be a bad idea I think
	//cout << "=ing signature" << endl;

	if ( mHavePrivateKey || mHavePublicKey ) {
		EC_KEY_free(eckey);
		eckey = NULL;
	}
	if ( ecsig != NULL ) {
		ECDSA_SIG_free(ecsig);
		ecsig = NULL;
	}	string key;

	// FIXME: there is a openssl copy function for keys; that would be much faster

	if ( rSig.mHavePrivateKey ) {
		key = rSig.GetPrivateKey();
		const unsigned char * keydata = reinterpret_cast<const unsigned char*>(key.data());
		SetPrivateKey(&keydata, key.length());
	} else {
		key = rSig.GetPublicKey();
		const unsigned char * keydata = reinterpret_cast<const unsigned char*>(key.data());
		SetPublicKey(&keydata, key.length());
	}


	assert(eckey != NULL);

	if ( rSig.mHaveSignedData) {
		//cout << "Sig present" << endl;
		SetSignature(rSig.GetSignature());
	}

	return *this;
}

/**
 * Destructor
 */
cSignature::~cSignature() {
	if (mHaveSignedData) {
		ECDSA_SIG_free(ecsig);
	}
	if ( mHavePrivateKey || mHavePublicKey ) {
		EC_KEY_free(eckey);
		eckey = NULL;
	}
}

/**
 * Set the private key.
 *
 * \param key the key
 * \param keylen length of key data
 */
void cSignature::SetPrivateKey(const unsigned char** key, uint32_t keylen) {
	if ( mHavePrivateKey || mHavePublicKey ) {
		EC_KEY_free(eckey);
	}
	eckey = NULL;
	eckey = d2i_ECPrivateKey(&eckey, key, keylen);
	mHavePrivateKey = true;
	mHaveSignedData = false;
}

/**
 * Set the public key (wrapper for second function)
 *
 * \param mNewSig new public key
 */
void cSignature::SetPublicKey(const string & mNewSig) {
	const unsigned char * key = reinterpret_cast<const unsigned char*>(mNewSig.data());

	SetPublicKey(&key, mNewSig.size());
}

/**
 * Set the public key
 *
 * \param key the new key
 * \param keylen length of key data
 */
void cSignature::SetPublicKey(const unsigned char** key, uint32_t keylen) {
	if ( mHavePrivateKey || mHavePublicKey ) {
		EC_KEY_free(eckey);
	}
	eckey = NULL;
	eckey = EC_KEY_new_by_curve_name(ECCURVENAME);
	eckey = o2i_ECPublicKey(&eckey, key, keylen);
	assert(eckey != NULL);
	mHavePrivateKey = false;
	mHavePublicKey = true;
	mHaveSignedData = false;
}

/**
 * Mainly for debugging purposes; print key information to stdout
 */
void cSignature::PrintECInformation() const
{
	cout << "----------------------------------- EC KEY INFORMATION START" << endl;
	EC_KEY_print_fp(stdout, eckey, 0);
	cout << "----------------------------------- EC KEY INFORMATION END" << endl << endl;

}

/**
 * Sign a (20 Bytes long) SHA-1 Hash
 *
 * \param hash hash data
 * \todo "20" is defined somewhere in the openssl sources
 */
void cSignature::SignSHA1Hash(const unsigned char *hash) {
	// and now we generate the ec-signature

	if ( ecsig != NULL ) {
		ECDSA_SIG_free(ecsig);
	}

	assert(eckey != NULL);
        ecsig = ECDSA_do_sign(hash, 20, eckey);
	assert(ecsig != NULL);
	int ret = ECDSA_do_verify(hash, 20, ecsig, eckey);
	assert (ret == 1); // 1 = do_verify ok.

	mHaveSignedData = true;
}

/**
 * Verify an (20 Bytes long) SHA-1 Hash
 *
 * \param hash hash data
 * \return 1 on success
 * \todo "20" is defined somewhere in the openssl sources
 */
int cSignature::VerifySHA1Hash(const unsigned char *hash) const {
	if ( ! ( (ecsig != NULL) && ( eckey != NULL) ) ) {
		// either ecsig or eckey is NULL
#ifdef VERBOSE_ERRORS
		cerr << "Signature: trying to verify Signature where no signature or key is present" << endl;
		if ( ecsig == NULL ) {
			cerr << "Signature: NULL ";
		}
		if ( eckey == NULL ) {
			cerr << "Key: NULL ";
		}
		cerr << endl;
#endif
		return -1;
	}

	int ret = ECDSA_do_verify(hash, 20, ecsig, eckey); // 1 valid, 0 invalud, -1 error
	return ret;
}

/**
 * Get length of the public key data when exported
 *
 * \return length
 */
int cSignature::GetPublicKeyLength() const {
	if ( eckey != NULL ) {
		return i2o_ECPublicKey(eckey, NULL);
	} else {
#ifdef VERBOSE_ERRORS
		cerr << "Signature: trying to get length of emtpy key" << endl;
#endif
		return 0;
	}
}

/**
 * Get length of the private key data when exported
 *
 * \return length
 */
int cSignature::GetPrivateKeyLength() const {
	if ( eckey != NULL ) {
		return i2d_ECPrivateKey(eckey, NULL);
	} else {
#ifdef VERBOSE_ERRORS
		cerr << "Signature: trying to get length of emtpy key" << endl;
#endif
		return 0;
	}
}

/**
 * Get Public key data
 *
 * \return public key data
 */
string cSignature::GetPublicKey() const {
	int public_key_length;
	unsigned char *public_key;
	string result;

	if ( eckey == NULL ) {
#ifdef VERBOSE_ERRORS
		cerr << "Trying to get empty key" << endl;
#endif
		return "";
	}

	public_key_length = GetPublicKeyLength();
	//public_key = new unsigned char[public_key_length];
	public_key = NULL;
	assert(i2o_ECPublicKey(eckey, &public_key));

	result.assign((char*)public_key, public_key_length);
	OPENSSL_free(public_key);
	return result;
}

/**
 * Get private key data
 *
 * \param pkey key will be stored here
 */
void cSignature::GetPrivateKey(unsigned char **pkey) {
	if ( eckey != NULL ) {
		assert(i2d_ECPrivateKey(eckey, pkey));
	} else {
#ifdef VERBOSE_ERRORS
		cerr << "Signature: trying to get emtpy key" << endl;
#endif
		return;
	}
}

/**
 * Get private key data
 *
 * \return public key data
 */
string cSignature::GetPrivateKey() const {
	int private_key_length;
	unsigned char *private_key;
	string result;

	if ( eckey == NULL ) {
#ifdef VERBOSE_ERRORS
		cerr << "Trying to get empty key" << endl;
#endif
		return "";
	}

	private_key_length = GetPrivateKeyLength();
	//public_key = new unsigned char[public_key_length];
	private_key = NULL;
	assert(i2d_ECPrivateKey(eckey, &private_key));

	result.assign((char*)private_key, private_key_length);
	OPENSSL_free(private_key);
	return result;
}

/**
 * Get signature data
 *
 * \return signature data
 */
string cSignature::GetSignature() const {
	int length;
	unsigned char* sig;
	unsigned char* origsig;
	string result;

	if ( (eckey == NULL) || (ecsig == NULL) ) {
#ifdef VERBOSE_ERRORS
		cerr << "Trying to get signature with empty key or sig!" << endl;
#endif
		return "";
	}

	length = i2d_ECDSA_SIG(ecsig, NULL);
	assert ( length != 0);
	origsig = sig = new unsigned char[length];
	i2d_ECDSA_SIG(ecsig, &sig);

	result.assign(reinterpret_cast<char*>(origsig), length); // origsig, because openssl changes sig...

	delete[] origsig; // openssl pfuscht am originalem pointer rum.

	return result;
}

/**
 * Set signature data
 *
 * \param rNewSig new Signature
 */
void cSignature::SetSignature(const string &rNewSig) {
	if ( ecsig != NULL ) {
		ECDSA_SIG_free(ecsig);
		ecsig = NULL;
	}

	unsigned char *thesig = new unsigned char[rNewSig.length()];
	unsigned char *origsig = thesig;
	memcpy(thesig, rNewSig.data(), rNewSig.length());
	d2i_ECDSA_SIG(&ecsig, const_cast<const unsigned char**>(&thesig), rNewSig.length());

	delete [] origsig;
	mHaveSignedData = true;
}

/**
 * Set signature data
 *
 * \param pp signature data
 * \param l signature data length
 */
void cSignature::SetSignature(const unsigned char **pp, uint32_t l) {
	if ( ecsig != NULL ) {
		ECDSA_SIG_free(ecsig);
		ecsig = NULL;
	}

	//ecsig = ECDSA_SIG_new();
	ecsig = d2i_ECDSA_SIG(&ecsig, pp, l);
	assert ( ecsig != NULL );
	mHaveSignedData = true;
}

/**
 * Export Signature and public key.
 *
 * \return signature and public key
 */
string
cSignature::ExportSignature() const {
	uint32_t public_key_length; // uint32 is kind of overkill... but nevermind.
	uint32_t signature_length;
	string result;

	if ( (eckey == NULL) ) {
#ifdef VERBOSE_ERRORS
		cerr << "Trying to export signature with empty key" << endl;
#endif
		return "";
	}

	string public_key = GetPublicKey();
	string signature;

	public_key_length = public_key.size();

	if ( mHaveSignedData ) {
		signature = GetSignature();
		signature_length = signature.size();
	} else {
		signature_length = 0;
	}

	public_key_length = htonl(public_key_length);
	signature_length = htonl(signature_length);

	result.assign(reinterpret_cast<const char*>(&public_key_length), sizeof(uint32_t));
	result += public_key;
	result.append(reinterpret_cast<const char*>(&signature_length), sizeof(uint32_t));
	if ( mHaveSignedData ) {
		result += signature;
	}

	return result;
}

/**
 * Import data exported by ExportSignature
 *
 * \param mData new public key and signature
 */
void
cSignature::ImportSignature(const string & mData) {
	uint32_t public_key_length;
	uint32_t signature_length;

	mData.copy(reinterpret_cast<char*>(&public_key_length), sizeof(uint32_t));
	public_key_length = ntohl(public_key_length);
	string public_key(mData, sizeof(uint32_t), public_key_length);
	mData.copy(reinterpret_cast<char*>(&signature_length), sizeof(uint32_t), sizeof(uint32_t)+public_key_length);
	signature_length = ntohl(signature_length);

	SetPublicKey(public_key);

	if ( signature_length > 0 ) {
		string signature(mData, sizeof(uint32_t)*2+public_key_length, signature_length);

		SetSignature(signature);
	}
}

/** @} */
