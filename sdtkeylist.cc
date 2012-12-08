// stuff for the SD-publisher and client
//
// Johanna Amann <johanna@0xxon.net>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sdtkeylist.hh"
#include <iostream>
#include <cstring> /* for bzero */
#include <strings.h> /* ditto. solaris. pendantic. */

using namespace std;

/**
 * standard constructur
 */
cSDTreeKeyList::cSDTreeKeyList() {
	mSig = new cSignature();
	assert ( mSig != NULL );
	InitKeyList();
}

/**
 * initialize the keylist with the current number of keys
 */
void cSDTreeKeyList::InitKeyList()
{
	num_keys = (cSDTreeCommon::tree_height*(cSDTreeCommon::tree_height+1))/2; // exakt soviele keys wie wir f�r einen neuen client brauchen;
	keylist = new cSDTreeCommon::keyEntry[num_keys];
	memset(keylist, 0, sizeof(cSDTreeCommon::keyEntry) * num_keys);

	//keylisthash = new unsigned char[KEYLISTHASHLENGTH]; // SHA-1 hash
	//bzero(keylisthash, 32);
}

/**
 * Destructor
 */
/* virtual */
cSDTreeKeyList::~cSDTreeKeyList() {
	delete[] keylist;
	delete mSig;
}

/**
 * Mainly for debugging: output the Information of the EC Key to stdout
 */
void cSDTreeKeyList::PrintECInformation() const
{
        mSig->PrintECInformation();
}

/**
 * Mainly for debugging: Print the Content of the Keylist to stdout
 */
void cSDTreeKeyList::PrintKeylist() const
{
	cout << "----------------------------------- KEYLIST START" << endl;
	for (int i = 0; i < num_keys; i++) {
		string keyvalue = cSDTreeCommon::CharToHex(keylist[i].key, cSDTreeCommon::aes_bits/(8*sizeof(char)));
		cout << "Key with path " << cSDTreeCommon::PathToString(keylist[i].path) << " subsetdepth " << keylist[i].subsetdepth << " differencedepth " << keylist[i].differencedepth << " has value " <<keyvalue << endl;
	}
	cout << "----------------------------------- KEYLIST END" << endl;
}

/**
 * Sign data contained in rData with our EC-Key. Returns newly allocated cSignature structure.
 *
 * \param rData data to sign
 * \return new cSignature with signed data
 */
cSignature
cSDTreeKeyList::SignData(const string & rData) const
{
	cSignature newSig;
	newSig = *mSig;
	string ourHash = cSDTreeCommon::SHA1Hash(rData);
	newSig.SignSHA1Hash(reinterpret_cast<const unsigned char*>(ourHash.c_str()));

	return newSig;
}

/**
 * Sign Hash provided. Has to be 20 Bytes long.
 *
 * \param rData 20 bytes long hash to sign
 * \return cSignature that has signed this hash.
 */
cSignature
cSDTreeKeyList::SignHash(const string & rData) const
{
	cSignature newSig;
	assert(rData.length() == 20);
	newSig = *mSig;
	newSig.SignSHA1Hash(reinterpret_cast<const unsigned char*>(rData.c_str()));

	return newSig;
}

/**
 * return a copy of mSig
 *
 * \return copy of mSig
 */
cSignature
cSDTreeKeyList::GetSignature() const
{
	cSignature newsig;
	newsig = *mSig;
	return newsig;
}

/**
 * Get function for member mFsRev
 *
 * \return mFsRev
 */
uint32_t
cSDTreeKeyList::GetMajorRevision() const
{
	return mFsRev;
}

/** @} */
