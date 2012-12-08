// stuff that is needed by nearly everything that handles the Subset Difference Algorithm
//
// Johanna Amann <johanna@0xxon.net>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sdtcommon.hh"
#include <openssl/aes.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <iostream>
#include <openssl/sha.h>
#include <fstream>

// this line yells loudly, that we are using urandom. Please disable only, if not using urandom
#ifdef ENABLE_DEBUG /* use urandom when debugging cause we will probably restart quite often */
	#define RANDOMFILE "/dev/urandom"
	#define COMPLAIN_URANDOM
/*	#warning using /dev/urandom, key generation not save */
#else /* ENABLE_DEBUG */
// if used in productive setting, change to /dev/random!
	#define RANDOMFILE "/dev/urandom"
#endif /* ENABLE_DEBUG */

using namespace std;

cSDTreeCommon::RandomBytesFunction *cSDTreeCommon::randomBytesFunction = &cSDTreeCommon::DefaultRandomBytesFunction;

/**
 * Use AES in Counter mode
 *
 * \param ctr the counter to use
 * \param key the key to use and the return value
 */
void cSDTreeCommon::AESctr(const unsigned char *ctr, unsigned char *key) {
	AES_KEY aeskey;
	unsigned char *out = new unsigned char[aes_bits/8];
	memset(out, 0, aes_bits/8);

	AES_set_encrypt_key(key, aes_bits, &aeskey);
	AES_encrypt(ctr, out, &aeskey);
	//cout << "aes direct output " << CharToHex(out, 16) << endl;

	memcpy(key, out, aes_bits/8);
	delete[] out;
}

/**
 * AES encrypt message
 *
 * \param rMsg message to encrypt
 * \param key key to use
 * \param out resulting message is written here (ATTN: can need more space than rMsg)
 */
void cSDTreeCommon::AESEncryptKey(const unsigned char *rMsg, const unsigned char *key, unsigned char *out) {
	AES_KEY aeskey;
	memset(out, 0, aes_bits/8);

	AES_set_encrypt_key(key, aes_bits, &aeskey);
	AES_encrypt(rMsg, out, &aeskey);
}

/**
 * AES decrypt message
 *
 * \param rMsg message to decrypt
 * \param key key to use
 * \param out resulting message is written here
 */
void cSDTreeCommon::AESDecryptKey(const unsigned char *rMsg, const unsigned char *key, unsigned char *out) {
	AES_KEY aeskey;
	memset(out, 0, aes_bits/8);

	AES_set_decrypt_key(key, aes_bits, &aeskey);
	AES_decrypt(rMsg, out, &aeskey);
}

/**
 * calculate a left node in our tree
 *
 * \param key to calculate left node of; output is also written here
 */
void cSDTreeCommon::left(unsigned char *key)
{
	unsigned char *counter = new unsigned char[aes_bits/8];
	memset(counter, 0, aes_bits/8);

	counter[0] = 1; // left => 1

	AESctr(counter, key);
	delete[] counter;
}

/**
 * calculate a center node in our tree
 *
 * \param key to calculate center node of; output is also written here
 */
void cSDTreeCommon::center(unsigned char *key)
{
	unsigned char *counter = new unsigned char[aes_bits/8];
	memset(counter, 0, aes_bits/8);

	counter[0] = 2; // left => 1

	AESctr(counter, key);
	delete[] counter;
}

/**
 * calculate a right node in our tree
 *
 * \param key to calculate right node of; output is also written here
 */
void cSDTreeCommon::right(unsigned char *key)
{
	unsigned char *counter = new unsigned char[aes_bits/8];
	memset(counter, 0, aes_bits/8);

	counter[0] = 3; // left => 1

	AESctr(counter, key);
	delete[] counter;
}

/**
 * Convert a path to a string representing it
 *
 * \param path path to convert
 * \return string equivalent
 */
string cSDTreeCommon::PathToString(const tPath path)
{
	string result = "";

	for (unsigned int depth = 0; depth < tree_height; depth++)
	{
		if ( path & ( 1 << depth ) )
		{
			result = "1" + result;
		} else {
			result = "0" + result;
		}
	}

	return result;
}

/**
 * Convert a string representation of a path
 *
 * \param in string representation
 * \return the path
 */
tPath cSDTreeCommon::StringToPath(const string &in)
{
	assert(in.length() == tree_height);
	tPath newkey = 0;
	unsigned int count=0;

	for(int i = tree_height-1; i >= 0; i--)  // der Baum wird bei uns von unten aufgebaut :)
	{
		if (in.at(i) == '1') {
			newkey = newkey | ( 1 << count );
		}
		count++;
	}

	return newkey;
}

/**
 * Convert a double path to a string. Pay attention to the bit ordering of Path and DoublePath.
 * It may be reversed
 *
 * \param path the path to convert
 * \return string representation
 */
string cSDTreeCommon::DoublePathToString(const tDPath path)
{
	string result = "R";

	for (unsigned int depth = 0; depth < 2*tree_height; depth++)
	{
		if ( path & ( (tDPath)1 << depth ) )
		{
			result = "1" + result;
		} else {
			result = "0" + result;
		}
	}

	return result;
}

/**
 * Convert a string to a double path
 * Attention: the numbers of StringToPath and StringToDoublePath have different bit ordering!
 *
 * \param in string to convert
 * \return doublepath
 */
tDPath cSDTreeCommon::StringToDoublePath(const string &in)
{
	assert(in.length() == tree_height);
	tDPath newkey = 0;

	for(unsigned int i = 0; i < tree_height; i++)  // der Baum wird bei uns von unten aufgebaut :)
	{
		if (in.at(i) == '1') {
			newkey = newkey | ( (tDPath)1 << (2*i) );
		}
	}

	return newkey;
}

/**
 * Convert a char array to hex numbers.
 * don't forget to free the result.
 * \todo replace this with something else? Where is it needed?
 */
std::string cSDTreeCommon::CharToHex(const unsigned char *m, const int size)
{
	char *res;
	int i;

	res = new char[(size*2)*sizeof(char) + 1];
	memset(res, 0, (size*2)*sizeof(char) + 1);
	//res = (char*) malloc((size*2) * sizeof(char *));
	for (i=0; i<size; i++)
		sprintf(res+ i*2, "%02X", m[i]);

	std::string resstring(res, (size*2)*sizeof(char) + 1);
	delete[] res;

	return resstring;
}

/**
 * get the layer that is covered (that means the highest layer-but that is set to true)
 *
 * \param path the double path
 * \return layer that is covered
 */
int cSDTreeCommon::GetLayer(tDPath path)
{
	tDPath maskedpath = ( (tDPath)0xAAAAAAAAAAAAAAAALL ) & path;
	int count = 0;

	for ( int i = (int)tree_height - 1; i>=0; i--) {
		if ( (tDPath) maskedpath & ( (tDPath) 1 << ( (2*i) + 1 ) ) ) {
			//cout << "Path: " << DoublePathToString( maskedpath & ( (tDPath) 1 << ( (2*i) + 1 ) ) ) << endl;
			//cout << "I is " << i << endl;
			return count;
		}
		count++;
	}

	return count;
}

/**
 * Convert a DoublePath to a Path
 *
 * \param path the doublepath
 * \return single path representation
 */
tPath cSDTreeCommon::DoublePathToPath(tDPath path)
{
	tPath newpath = 0x0L;
 	int count = 0;
	for ( int i = ( static_cast<int>(tree_height)) - 1; i >= 0; i-- )
	{
		if ( path & ( (tDPath) 1 << 2*i) )
		{
			 newpath |= (tPath) 1 << count;
		}
		count++;
	}

	return newpath;
}

/**
 * AES encrypt a message in cbc mode
 *
 * \param message the message to encrypt
 * \param aesmasterkey the aes key to use
 * \param aesmasterkeyiv the iv for the key to use
 * \return encrypted message
 */
string cSDTreeCommon::AESEncryptMessage(const string &message, const unsigned char* aesmasterkey, unsigned char* aesmasterkeyiv)
{
	AES_KEY aeskey;
	int newsize = message.size() + (cSDTreeCommon::aes_bits/8) - message.size() % (cSDTreeCommon::aes_bits/8);
	//cerr << "Newsize for message is " << newsize << endl;
	//cerr << "String length is " << message.size() << endl;


	string result;
	//unsigned char *messagechar = new unsigned char[message.size()];
	//unsigned char *messagecharsaved = messagechar;
	unsigned char *resultchar = new unsigned char[newsize];
	memset(resultchar, 59, newsize);
	memcpy(resultchar, message.data(), message.size());

	AES_set_encrypt_key(aesmasterkey,cSDTreeCommon::aes_bits, &aeskey);
	//AES_cbc_encrypt((unsigned char*)resultchar, resultchar, message.size(), &aeskey, aesmasterkeyiv, AES_ENCRYPT);
	// openssl 1.0 dos not like if we give it the real message size. use padded size instead.
	AES_cbc_encrypt((unsigned char*)resultchar, resultchar, newsize, &aeskey, aesmasterkeyiv, AES_ENCRYPT);


	result.assign((char*)resultchar, newsize);  // I hope this works...
	delete [] resultchar;
	//delete [] messagecharsaved;

	return result;

}

/**
 * AES decrypt a message in cbc mode
 *
 * The size of the message is needed because it can be shorter than the encrypted message.
 * (encrypted message is always a multiple of the blocksize)
 *
 * \param message the message to decrypt
 * \param size size of the decrypted message
 * \param aesmasterkey the aes key to use
 * \param aesmasterkeyiv the iv for the key to use
 * \return decrypted message
 */
string cSDTreeCommon::AESDecryptMessage(const string &message, int size, const unsigned char* aesmasterkey, unsigned char* aesmasterkeyiv)
{
	AES_KEY aeskey;

	string result;
	unsigned char *resultchar = new unsigned char[message.size()];

	AES_set_decrypt_key(aesmasterkey,cSDTreeCommon::aes_bits, &aeskey);
	AES_cbc_encrypt((unsigned char*)message.c_str(), resultchar, size, &aeskey, aesmasterkeyiv, AES_DECRYPT);


	result.assign((char*)resultchar, size);  // I hope this works...
	delete [] resultchar;

	return result;

}

/**
 * Calculate SHA1 hash of data.
 *
 * \param data data to hash
 * \param datasize length of data
 * \param hash the hash will be written here
 */
void cSDTreeCommon::SHA1Hash(const void *data, const int datasize, unsigned char *hash) {
	SHA_CTX sha;
	SHA1_Init(&sha);
	SHA1_Update(&sha, data, datasize);
	SHA1_Final(hash, &sha);
}

/**
 * Calculate SHA1 hash of data.
 *
 * \param data data to hash
 * \return hash
 */
string cSDTreeCommon::SHA1Hash(const string &data) {
	SHA_CTX sha;

	const char * in = data.c_str();
	unsigned char * out = new unsigned char[SHA_DIGEST_LENGTH];
	string reply;

	SHA1_Init(&sha);
	SHA1_Update(&sha, in, data.size());
	SHA1_Final(out, &sha);

	reply.assign(reinterpret_cast<const char*>(out), SHA_DIGEST_LENGTH);
	delete[] out;
	return reply;
}

/**
 * Calculate SHA256 hash of data.
 *
 * \param data data to hash
 * \return hash
 */
string cSDTreeCommon::SHA256Hash(const string &data) {
	SHA256_CTX sha;

	const char * in = data.c_str();
	unsigned char * out = new unsigned char[SHA256_DIGEST_LENGTH];
	string reply;

	SHA256_Init(&sha);
	SHA256_Update(&sha, in, data.size());
	SHA256_Final(out, &sha);

	reply.assign(reinterpret_cast<const char*>(out), SHA256_DIGEST_LENGTH);
	delete[] out;
	return reply;
}

void cSDTreeCommon::DefaultRandomBytesFunction(unsigned int number, unsigned char *bytes) {
#ifdef COMPLAIN_URANDOM
	cerr << "using /dev/urandom, key generation is not save at the moment" << endl << flush;
#endif
	// TODO default should probably better use the openssl RAND functions
	ifstream randomfile(RANDOMFILE, ios::binary);
	assert(randomfile.is_open());
	randomfile.read((char*)bytes, number);
	randomfile.close();
}

/** @} */
