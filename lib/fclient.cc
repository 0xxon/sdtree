// For client:
// implementation of filesystem location block decryption class
// Todo: Bit ordering in Binary data!
// 
// Johanna Amann <johanna@0xxon.net>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fclient.hh"

#include <string>
#include <iostream>
#include <fstream>
#include <string.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

// #define DEBUGOUTPUT

using namespace std;

void cFClient::LoadClientData(istream &stream) {
	uint32_t public_key_length;
	unsigned char* public_key;
	unsigned char* pkdel;

	stream.read(reinterpret_cast<char*>(&public_key_length), sizeof(uint32_t));
	pkdel = public_key = new unsigned char[public_key_length];
	stream.read(reinterpret_cast<char*>(public_key), public_key_length);
	stream.read(reinterpret_cast<char*>(&ourPath), sizeof(tPath));
	stream.read(reinterpret_cast<char*>(keylist), sizeof(cSDTreeCommon::keyEntry)*num_keys);

#ifdef DEBUGOUTPUT
	cout << "Public key length is " << public_key_length << endl;
#endif
	assert ( mSig != NULL );
	mSig->SetPublicKey(const_cast<const unsigned char**>(&public_key), public_key_length);
	message = NULL;
	masterkey = NULL;
	delete[] pkdel; // FIXME: throws error if you do SetPublicKey
}

/**
 * loads client data and verifies signature
 *
 * \param data - the data to parse
 * \return true on success; false otherwise
 */
bool cFClient::ParseSDTData(const string &data) {
	if ( message != NULL ) {
		delete[] message;
	}

	message = new unsigned char[data.size()];
	unsigned char * origmessage = new unsigned char[data.size()];

	uint32_t* blockID;
	uint32_t* public_key_length;
	//uint32_t* minor;
	uint32_t* major;
	unsigned char* public_key;
	unsigned char* position;
	unsigned char *hash = new unsigned char[20];
	uint32_t* signature_length;
	unsigned char *signature;
	int hashreturn;

#ifdef DEBUGOUTPUT
	cout << "Datasize: " << data.size() << endl;
#endif

	assert( sizeof(unsigned char) == 1 ); // ok, this is probably plainly stupid.

	memcpy(message, data.data(), data.size());
	memcpy(origmessage, message, data.size());

	position = message;
	blockID = reinterpret_cast<uint32_t*>(position);
	*blockID = ntohl(*blockID);
	position += sizeof(uint32_t);
	if ( *blockID != 77235 ) { // our magic number
		// this does not belong to us...
		delete[] message;
		delete[] origmessage;
		delete[] hash;
		message = NULL;
		return false;
	}
	major = reinterpret_cast<uint32_t*>(position);
	*major = ntohl(*major);
	position += sizeof(uint32_t);
	//minor = reinterpret_cast<uint32_t*>(position);
	//*minor = ntohl(*minor);
	//position += sizeof(uint32_t);

	mFsRev = *major;
#ifdef DEBUGOUTPUT
	cout << "Decoded file System major Revision: " << mFsRev << endl;
#endif
	//mFsMRev = *minor;

	public_key_length = reinterpret_cast<uint32_t*>(position);
	*public_key_length = ntohl(*public_key_length);
	assert ( *public_key_length > 0 );
	position += sizeof(uint32_t);
	public_key = position;
	position += *public_key_length;
	sdkeylist_size = reinterpret_cast<uint32_t*>(position);
	*sdkeylist_size = ntohl(*sdkeylist_size);
	position += sizeof(uint32_t);
	sdkeylist = reinterpret_cast<cSDTreeCommon::nodeId*>(position);
	position += (*sdkeylist_size)*sizeof(cSDTreeCommon::nodeId);
#ifdef DEBUGOUTPUT
	cerr << "CoverKeyListSizePosition: " << (position-message) << endl;
#endif
	coverKeyList = reinterpret_cast<cSDTreeCommon::coverKey*>(position);
	position += (*sdkeylist_size)*sizeof(cSDTreeCommon::coverKey);
#ifdef DEBUGOUTPUT
	cerr << "CoverKeyListEndSizePosition: " << (position-message) << endl;
#endif
	aesmessage_size = *(reinterpret_cast<uint32_t*>(position));
	aesmessage_size = ntohl(aesmessage_size);
	position += sizeof(uint32_t);
	aesiv = position;
	aesmessage = position + cSDTreeCommon::aes_bits/8;
	position += aesmessage_size;
	(aesmessage_size) = (aesmessage_size) - cSDTreeCommon::aes_bits/8;
	position += (cSDTreeCommon::aes_bits/8) - aesmessage_size % (cSDTreeCommon::aes_bits/8); // the block is padded to full 16 bits; aes needs this.
#ifdef DEBUGOUTPUT
	cerr << "Encrypted Message size: " << aesmessage_size << endl;

	cerr << "Hashlength: " << position - message << endl;
#endif
	cSDTreeCommon::SHA1Hash(origmessage, position - message, hash);
#ifdef DEBUGOUTPUT
	cerr << "Hash: " << cSDTreeCommon::CharToHex(hash, 20) << endl;
#endif

	signature_length = reinterpret_cast<uint32_t*>(position);
	*signature_length = ntohl(*signature_length);
	position += sizeof(uint32_t);
	signature = position;
#ifdef DEBUGOUTPUT
	cout << "SigL: " << *signature_length << " SDK: " << *sdkeylist_size << " messagesize: " << aesmessage_size << endl;
#endif

	mSig->SetSignature(const_cast<const unsigned char**>(&signature), *signature_length);
#ifdef DEBUGOUTPUT
	cout << "lebe noch" << endl;
#endif
	hashreturn = mSig->VerifySHA1Hash(hash);
	//hashreturn = 1;
	//assert( hashreturn == 1 ); // if this works, we just verified the signature on the block :)
	if ( hashreturn != 1) {
		throw cSDTreeCommon::ClientException("Block has got correct magic number, but hash does not match");
	}

#ifdef DEBUGOUTPUT
	cerr << "Public key length: " << (*public_key_length) << endl;
#endif

	delete[] origmessage;
	delete[] hash;

	if ( hashreturn == 1 ) {
		return true;
	} else {
		return false;
	}
}

/**
 * loads client data and verifies signature
 *
 * \param data - the data to parse
 * \return true on success; false otherwise
 */
bool cFClient::ParseSData(const string &data) {
	if ( message != NULL ) {
		delete[] message;
	}

	message = new unsigned char[data.size()];
	unsigned char * origmessage = new unsigned char[data.size()];

	uint32_t* blockID;
	unsigned char* position;

#ifdef DEBUGOUTPUT
	cout << "Datasize: " << data.size() << endl;
#endif

	assert( sizeof(unsigned char) == 1 ); // ok, this is probably plainly stupid.

	memcpy(message, data.data(), data.size());
	memcpy(origmessage, message, data.size());

	position = message;
	blockID = reinterpret_cast<uint32_t*>(position);
	*blockID = ntohl(*blockID);
	position += sizeof(uint32_t);
	if ( *blockID != 77237 ) { // our magic number
#ifdef DEBUGOUTPUT
	cout << "Unknown magic number: " << *blockID << endl;
#endif
		// this does not belong to us...
		delete[] message;
		delete[] origmessage;
		return false;
	}

#ifdef DEBUGOUTPUT
	cout << "Correct magic number for short block: " << *blockID << endl;
#endif
	aesmessage_size = *(reinterpret_cast<uint32_t*>(position));
	aesmessage_size = ntohl(aesmessage_size);
	position += sizeof(uint32_t);
	aesiv = position;
	aesmessage = position + cSDTreeCommon::aes_bits/8;
	position += aesmessage_size;
	(aesmessage_size) = (aesmessage_size) - cSDTreeCommon::aes_bits/8;
	position += (cSDTreeCommon::aes_bits/8) - aesmessage_size % (cSDTreeCommon::aes_bits/8); // the block is padded to full 16 bits; aes needs this.
#ifdef DEBUGOUTPUT
	cerr << "Encrypted Message size: " << aesmessage_size << endl;

	//cout << "Hashlength: " << position - message << endl;
#endif

	delete[] origmessage;

	return true;
}

/**
 * search sdkeylist for a path that we can use to decrypt the data and return the number of that path
 *
 * \return 1 on success, 0 otherwise
 * \todo return value needs fixing.
 */
int cFClient::FindTreeBlock() {

	unsigned char resultkey[cSDTreeCommon::aes_bits/8];

	assert( sdkeylist_size != NULL );
	assert( sdkeylist != NULL );

#ifdef DEBUGOUTPUT
	cout << "Searching fitting Block..." << endl;
#endif

	// Attention! Bit-ordering:
	// highest-order-bit is leaf lowest-order-bit is root. ( I hope )
	for ( unsigned int i = 0; i < (*sdkeylist_size); i++) {

#ifdef DEBUGOUTPUT
		cout << "TestPath: " << cSDTreeCommon::PathToString(sdkeylist[i].path) <<  " subset " << sdkeylist[i].subsetdepth << " difference " << sdkeylist[i].differencedepth << endl;
#endif
		for ( int y = 0; y < num_keys; y++) {
			unsigned int depth = sdkeylist[i].subsetdepth;
			unsigned int differencedepth = sdkeylist[i].differencedepth;
			unsigned int mkddepth = (keylist[y]).differencedepth;
			tPath subsetmask = 0x0L;
			tPath differencemask = 0x0L;
			if ( (depth != (keylist[y]).subsetdepth)   || (mkddepth > differencedepth )   )
			{
				continue;
			}
#ifdef DEBUGOUTPUT
			cout << "Path 1: " << cSDTreeCommon::PathToString(sdkeylist[i].path) << " depth: " << depth  << " diff " << differencedepth << endl;
			cout << "Path 2: " << cSDTreeCommon::PathToString(keylist[y].path) << " depth: " << keylist[y].subsetdepth  << " diff " << keylist[y].differencedepth << endl;
#endif

			if ( mkddepth == 32 ) {
				subsetmask--;
			} else {
				subsetmask = (0x1L << mkddepth) - 1;
			}


			if ( differencedepth == 32 ) {
				differencemask--;
			} else {
				differencemask = ( 0x1L << differencedepth ) - 1;
			}

#ifdef DEBUGOUTPUT
			cout << "Path1m: " << cSDTreeCommon::PathToString( ( (sdkeylist[i]).path & ( subsetmask  ) ) ) << endl;
			cout << "Path2m: " << cSDTreeCommon::PathToString( ( (keylist[y]).path &  subsetmask ) ) << endl;
			cout << "Path1d: " << cSDTreeCommon::PathToString( ( (sdkeylist[i]).path & differencemask ) ) << endl;
			cout << "Path2d: " << cSDTreeCommon::PathToString( ( (keylist[y]).path & differencemask) ) << endl;
#endif

			bool test1 = (  sdkeylist[i].path & subsetmask ) == ( keylist[y].path & subsetmask );
			bool test2 = false;
			if ( differencedepth < 32) {
				test2 = (sdkeylist[i].path &  differencemask ) !=  (keylist[y].path & differencemask );
				test2 = true;
			} else {
				test2 = true;
			}


			//if (  ) && (  (sdkeylist[i]).path & ( differencemask ) !=  (keylist[y]).path & differencemask )   )
			//if ( (sdkeylist[i].path &  differencemask ) == (keylist[y].path & differencemask ))
			if ( test1 && test2 )
			{
#ifdef DEBUGOUTPUT
				cout << "Correct subset found at list position " << i << endl;
#endif
				GetKey(sdkeylist[i].path, keylist[y].key, mkddepth, differencedepth, reinterpret_cast<unsigned char*>(&resultkey));
				DecryptMasterKey(i, resultkey);
				return 1;
			}


		}
	}

	return 0;
}

/**
 * decrypt the master key at position i of the list with the key given.
 *
 * \param i position of the encrypted masterkey in the key list
 * \param key decryption key for the masterkey
 */
void cFClient::DecryptMasterKey(const unsigned int i, const unsigned char* key)
{
#ifdef DEBUGOUTPUT
	string keyvalue;
#endif
	if ( masterkey != NULL )
	{
		delete[] masterkey;
	}
#ifdef DEBUGOUTPUT
	cout << "Arg1: " << cSDTreeCommon::CharToHex(coverKeyList[i].key, cSDTreeCommon::aes_bits/(8*sizeof(char))) << endl;
	cout << "Arg1: " << cSDTreeCommon::CharToHex(key, cSDTreeCommon::aes_bits/(8*sizeof(char))) << endl;
#endif
	masterkey = new unsigned char[cSDTreeCommon::aes_bits/8];
	cSDTreeCommon::AESDecryptKey(coverKeyList[i].key, key, masterkey);
#ifdef DEBUGOUTPUT
	keyvalue = cSDTreeCommon::CharToHex(masterkey, cSDTreeCommon::aes_bits/(8*sizeof(char)));
	cerr << "AES Encryped Key value: " << keyvalue << endl;
#endif
}

/**
 * Decrypt an encrypted data block that is given to us.
 *
 * \param rData: encrypted data Block
 * \return decrypted data
 */
std::string cFClient::Decrypt(const std::string &rData) {

	if ( ParseSDTData(rData) == true ) { // first lets try, if this is an SD-Block
		if (! FindTreeBlock() ) {
			// we did not a path we can use for decryption...
			// -> throw exception and return

			throw cSDTreeCommon::ClientException("Could not find subset difference path for decryption");
		}

		string message = DecryptMessage();

#ifdef DEBUGOUTPUT
//		cout << "Message: " << message << endl;
#endif

		return message;
	} else if ( ParseSData(rData) == true) { // second try :)
		string message = DecryptMessage();
#ifdef DEBUGOUTPUT
//		cout << "Message: " << message << endl;
#endif
		return message;

	} else { // well, it didn't work. thats sad...
		throw cSDTreeCommon::ClientException("Could not decrypt message - neither short nor long block magic numbers did match");
	}

}

/**
 * called by Decrypt - calls the AES Decryption function with our message and the found key as parameters
 *
 * \return Decrypted Message
 */
string cFClient::DecryptMessage()
{
	string encmessage;
	encmessage.assign(reinterpret_cast<char*>(aesmessage), aesmessage_size-(cSDTreeCommon::aes_bits) % 16 + 16);

	return cSDTreeCommon::AESDecryptMessage(encmessage, aesmessage_size, masterkey, aesiv);
}

cFClient::cFClient(istream &stream) : cSDTreeKeyList()
{
	LoadClientData(stream);

	mFsRev = 0;
	//mFsMRev = 0;
}

/**
 * Constructor; construct the class and use keyfile to load our list of keys
 *
 * \param keyfile location of the file that contains our keys
 */
cFClient::cFClient(const string &keyfile) : cSDTreeKeyList()
{
	ifstream file;
	file.open(keyfile.c_str(), ios::binary);
	if ( ! file.is_open() )
		throw cSDTreeCommon::ClientException("Could not open client key file: "+keyfile);
	LoadClientData(file);
	file.close();

	mFsRev = 0;
	//mFsMRev = 0;
}

/**
 * This function is used to calculate a key further down in the tree from a higher-layer key.
 *
 * ATTENTION! Generates _CENTER_ Key
 *
 * \param path path of the key we want to get
 * \param pathkey key of the starting point
 * \param begindepth depth in tree at wich the pathkey is valid
 * \param enddepth depth of key we want to receive
 * \param key is used to return the result key
 */
void cFClient::GetKey(const tPath path, const unsigned char* pathkey, const unsigned int begindepth, const unsigned int enddepth, unsigned char *key)
{
	memcpy(key, pathkey, cSDTreeCommon::aes_bits/8);
	//cout << "begindepth: " << begindepth << " enddepth: " << enddepth << endl;
	//cout << "aeskey: " << cSDTreeCommon::CharToHex(key, 16) << endl;
	//cout << "aeskey: " << cSDTreeCommon::CharToHex(pathkey, 16) << endl;
	for ( unsigned int i = begindepth; i < enddepth; i++)
	{
		bool isset = path & ( (tPath) 0x1L << ( i ) );
		if ( isset ) {
			cSDTreeCommon::right(key);
			//cout << "Right " << endl;
		} else {
			cSDTreeCommon::left(key);
			//cout << "Left " << endl;
		}
		//cout << "aeskey: " << cSDTreeCommon::CharToHex(key, 16) << endl;

	}
#ifdef DEBUGOUTPUT
	cout << "aeskey: " << cSDTreeCommon::CharToHex(key, 16) << endl;
#endif
	cSDTreeCommon::center(key);
}

cFClient::~cFClient()
{
	if ( message != NULL ) {
		delete[] message;
	}
	if ( masterkey != NULL ) {
		delete[] masterkey;
	}
}

/** @} */
