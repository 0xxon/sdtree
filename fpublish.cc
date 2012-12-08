// For server:
// implementation of filesystem publisher block creation and manipulation class
// Todo: urandom -> random
// Todo: Bit ordering in Binary data!
//
// Johanna Amann <johanna@0xxon.net>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fpublish.hh"
#include <assert.h>

#include <iostream>
#include <fstream>
#include <set>
#include <string.h>
#ifdef WIN32
#include <winsock2.h> /* hton ntoh */
#else
#include <arpa/inet.h> /* hton ntoh */
#endif

// #define DEBUGOUTPUT

using namespace std;

void cFPublish::LoadServerData(std::istream &stream)
{
	uint32_t keylen;
	unsigned char *key;
	unsigned char *origkey;
	char *treesecret;
	uint32_t revocelist_length;
	uint32_t treesecret_length;
	aesmasterkey = NULL;
	aesmasterkeyiv = NULL;
	revokelistInvertedInMemory = false;
	//mFsMRev = 0;

	// eckey = EC_KEY_new_by_curve_name(ECCURVENAME); done by d2i_ECPrivateKey gemacht
	// assert(eckey != NULL);

	stream.read(reinterpret_cast<char*>(&keylen), sizeof(uint32_t));
	origkey = key = new unsigned char[keylen];
	stream.read(reinterpret_cast<char*>(key),keylen);
	stream.read(reinterpret_cast<char*>(&treesecret_length),sizeof(uint32_t));
	treesecret = new char[treesecret_length];
	stream.read(reinterpret_cast<char*>(treesecret), treesecret_length);
	stream.read(reinterpret_cast<char*>(&mFsRev), sizeof(uint32_t));
	stream.read(reinterpret_cast<char*>(&revocelist_length), sizeof(uint32_t));
	for (uint32_t i = 0; i < revocelist_length; i++)
	{
		tDPath newpath;
		stream.read(reinterpret_cast<char*>(&newpath), sizeof(tDPath));
		revokelist.insert(newpath);
		//cout << (newpath) << endl;
	}
	assert ( mSig != NULL);
        mSig->SetPrivateKey((const unsigned char**)&key, keylen);
	delete[] origkey;

	mTreeSecret.assign(treesecret, treesecret_length);
	delete[] treesecret;
#ifdef DEBUGOUTPUG
	cerr << "Tree secret: " << mTreeSecret << endl;
#endif

	// Load the saved aes master key
	int aes_keylen = cSDTreeCommon::aes_bits/8;
	if ( aesmasterkey == NULL ) {
		aesmasterkey = new unsigned char [aes_keylen];
	}

	stream.read(reinterpret_cast<char*>(aesmasterkey), aes_keylen);
	stream.read(reinterpret_cast<char*>(&revokelistInverted), sizeof(bool));

	if ( stream.fail() ) {
		throw cSDTreeCommon::PublishException("loading server data failed");
	}
}

/**
 * Initialize the AES Master Key from a random source.
 */
void cFPublish::InitAESMasterKey() {
	int keylen = cSDTreeCommon::aes_bits/8;

	if ( aesmasterkey == NULL ) {
		aesmasterkey = new unsigned char[keylen];
	}

	cSDTreeCommon::GetRandomBytes(keylen,aesmasterkey);
}

/**
 * Initialize the IV for the AES Master key; needed because we can have the
 * same key for several sessions but need a new IV for each one.
 *
 * We use urandom, because we use the number only as a nonce and create the iv
 * according to nist sp800-38a appendix c.
 */
void cFPublish::InitAESMasterKeyIv() {
	int keylen = cSDTreeCommon::aes_bits/8;

	if ( aesmasterkeyiv == NULL ) {
		aesmasterkeyiv = new unsigned char [keylen];
	}

	unsigned char* temprandom = new unsigned char[keylen];

	cSDTreeCommon::GetRandomBytes(keylen,temprandom);

	memcpy(reinterpret_cast<char*>(aesmasterkeyiv), reinterpret_cast<char*>(aesmasterkey), keylen);
	cSDTreeCommon::AESctr(temprandom, aesmasterkeyiv);
	delete[] temprandom;
}

/**
 * Standard Constructor
 */
cFPublish::cFPublish() : cSDTreeKeyList(), mTreeSecret()
{
	mFsRev = 0;
	revokelistInverted = false;
	revokelistInvertedInMemory = false;
	//mFsMRev = 0;
	aesmasterkey = NULL;
	aesmasterkeyiv = NULL;

	InitAESMasterKey();
	InitAESMasterKeyIv();
}

/**
 * Construct a new class from a input stream that contains our private key and the revocees.
 *
 * \param stream input stream that contains our keys and the revoced users
 */
cFPublish::cFPublish(istream &stream) {
	LoadServerData(stream);
	InitAESMasterKeyIv();
}

/**
 * Construct a new class from a file that contains our private key and the revocees.
 *
 * \param path path of the file that contains our keys and the revoced users
 */
cFPublish::cFPublish(string path) : cSDTreeKeyList(), mTreeSecret()
{
	ifstream file;
	file.open(path.c_str(), ios::binary);
	if ( ! file.is_open() ) {
		throw cSDTreeCommon::PublishException("can't open file '" + path + "'");
	}
	LoadServerData(file);
	file.close();
	InitAESMasterKeyIv();
}

/**
 * Destructor
 */
cFPublish::~cFPublish()
{
	delete[] aesmasterkey;
	delete[] aesmasterkeyiv;
}

/**
 * Function used mainly for debugging; Outputs the List of revoced keys to stdout
 */
void cFPublish::PrintSDKeyList()
{
	vector<cSDTreeCommon::keyEntry>::iterator it = sdkeylist.begin();

	cout << "----------------------------------- REVOCATION SDLIST START" << endl;
	while (it != sdkeylist.end()) {
		cSDTreeCommon::keyEntry e = *it;
		string keyvalue = cSDTreeCommon::CharToHex(e.key, cSDTreeCommon::aes_bits/(8*sizeof(char)));
		cout << "Key with path " << cSDTreeCommon::PathToString(e.path) << " subsetdepth " << e.subsetdepth << " differencedepth " << e.differencedepth << " has value " << keyvalue << endl;
		it++;
	}
	cout << "----------------------------------- REVOCATION SDLIST END" << endl;
}

/**
 * Generate the list of keys that the client will get from the path of the client.
 *
 * \param path path of client (attention! Bit ordering is not always the same)
 */
void cFPublish::generate_keylist(const tPath path)
{
	ourPath = path;
	unsigned int keynum = 0;
	assert(sizeof(tPath) == cSDTreeCommon::tree_height/8); // we have got a serious problem otherwise...

#ifdef DEBUGOUTPUT
	cout << "Generating keylist for path: " << cSDTreeCommon::PathToString(path) << endl << endl;
#endif

	/**
	 * This actually is quite simple; we have to be able to generate all keys in all
	 * subtrees of the tree we are a part of - but only if they are no direct
	 * predecessor of ourself.
	 *
	 * The algorithm that generates these keys is quite simple.
	 * We walk down the tree from the root to our target node (outer loop).
	 * After each step we add the key of the other child of the parent of the actual node to the
	 * keylist, and repeat this step for every possible parent of the actual node (inner loop)
	 */
	for(unsigned int depth = 0; depth <= cSDTreeCommon::tree_height; depth++)
	{
		for (unsigned int i = 0; i < depth; i++)
		{
			bool isset = path & ( 1 << ( depth - 1) );
			tPath keypath = path & ( ( 1 << ( depth - 1) ) - 1 ); // the path up to this node
			if ( !isset ) {
				keypath = keypath | ( 1 << ( depth - 1) ); // we always get the key of the node that is not on our path
			}
			keylist[keynum].path = keypath;
			keylist[keynum].subsetdepth = i;
			keylist[keynum].differencedepth = depth;
			GetKey(keypath, i, depth, keylist[keynum].key);

			//cout << "SubsetDepth " << i << " DifferenceDepth " << depth << " Path: " << cSDTreeCommon::PathToString(keypath) << endl;
			keynum++;
		}
	}

#ifdef DEBUGOUTPUT
	cout << "Generated " << keynum << " keys." << endl;
#endif
}

/**
 * Generate the Master keys (that means the keys that are at the top of each subtree)
 *
 * \todo perhaps change the algorith from md5 to a real random number alrogithm
 * \todo extension: longest-prefix-match secret
 */
void cFPublish::GetMasterKey(const tPath spath, const uint32_t depth, unsigned char *key) const
{
	tPath path = spath;
	// int datalength = sizeof(tPath) + sizeof(uint32_t) + mTreeSecret.length();
	string datatohash;
	uint32_t newdepth = htonl(depth);

	// this next few linkes have cost me many hours of bughunting *sigh*
	if ( depth < 32)
	{
		path &= ( (tPath)1 << depth ) -1;
	}
	// and that was not even that difficult, was it?

	datatohash = mTreeSecret;
	datatohash.append(reinterpret_cast<char*>(&path), sizeof(tPath));
	datatohash.append(reinterpret_cast<char*>(&newdepth), sizeof(uint32_t));
	string hashresult = cSDTreeCommon::SHA256Hash(datatohash);

	for ( int i = 0; i < 16; i++) {
		key[i] = hashresult[i]^hashresult[i+16];
	}

	//cout << "key: " << cSDTreeCommon::CharToHex(key, 32) << endl;
}

/**
 * Set function for mTreeSecret
 *
 * \param rnewTreeSecret the new secret
 */
void
cFPublish::SetTreeSecret(const string &rnewTreeSecret)
{
	mTreeSecret = rnewTreeSecret;
}

/**
 * Generate a key further down in the tree from a given key. Changes the key parameter that is proviced.
 *
 * \param path path of the key
 * \param subset subset depth (that means the depth of the starting key)
 * \param difference difference depth (depth of the key we want to get)
 * \param key given key and result key
 */
void cFPublish::GetKey(const tPath path, const unsigned int subset, const unsigned int difference, unsigned char *key) const
{
	GetMasterKey(path, subset, key);
	//cerr << "S " << subset << " D " << difference << endl;
	//cerr << "MasterKey: " << cSDTreeCommon::CharToHex(key, 16) << endl;
	for (unsigned int i = subset; i < difference; i++)
	{
		bool isset = path & ( 0x1L << ( i ) );
		if ( isset ) {
			cSDTreeCommon::right(key);
			//cerr << "right " << endl;
		} else {
			cSDTreeCommon::left(key);
			//cerr << "left " << endl;

		}
			//cerr << "MasterKey: " << cSDTreeCommon::CharToHex(key, 16) << endl;
	}
	//cerr << "aeskey: " << cSDTreeCommon::CharToHex(key, 32) << endl;
}

/**
 * Wrapper to call GetKey with a keyEntry type parameter
 *
 * \param entry entry to manipulate
 */
void cFPublish::GetKey(cSDTreeCommon::keyEntry *entry) const
{
	GetKey(entry->path, entry->subsetdepth, entry->differencedepth, entry->key);
}

/**
 * Generate a center key (simply generate the key with GetKey and gets the center
 * operated directly on parameter
 *
 * \param entry key to generate center from
 */
void cFPublish::GetCenterKey(cSDTreeCommon::keyEntry *entry) const
{
	GetKey(entry->path, entry->subsetdepth, entry->differencedepth, entry->key);
	cSDTreeCommon::center(entry->key);
}

/**
 * Generate a block, that is only encrypted with our AES key, without using the subset difference revocation scheme.
 * This can be used, if the major revision and hence the users that may access the new block did not change
 *
 * \param message message to enrypt
 * \return encrypted message
 */
string cFPublish::GenerateAESEncryptedBlock(const string &message) const {
	string result = "";
	uint32_t blockID = 77237; // our "Magic Number";
	blockID = htonl(blockID);
	uint32_t message_size;

	result.append(reinterpret_cast<const char*>(&blockID), sizeof(uint32_t));
	message_size = message.size() + cSDTreeCommon::aes_bits/8; // hinter dem + kommt die l�nge des IV
	message_size = htonl(message_size);
	result.append(reinterpret_cast<const char*>(&message_size), sizeof(uint32_t));
	result.append(reinterpret_cast<const char*>(aesmasterkeyiv), cSDTreeCommon::aes_bits/8);
        result += cSDTreeCommon::AESEncryptMessage(message, aesmasterkey, aesmasterkeyiv);

	return result;
}


/**
 * Generate the encrypted Subset Difference Block. Encrypts a message and prepends things like the magic number
 * and all the information that is needed for a client to be able to decrypt the message lateron.
 *
 * \param message message to enrypt
 * \return encrypted message
 */
string cFPublish::GenerateSDTreeBlock(const string &message) {
	string result = "";
	uint32_t blockID = 77235; // our "Magic Number";
	blockID = htonl(blockID);
        uint32_t public_key_length = mSig->GetPublicKeyLength();
	public_key_length = htonl(public_key_length);
        uint32_t sdkeylistsize = sdkeylist.size();
        cSDTreeCommon::coverKey* coverKeyList;
        coverKeyList = new cSDTreeCommon::coverKey[sdkeylistsize];
	sdkeylistsize = htonl(sdkeylistsize);
        vector<cSDTreeCommon::keyEntry>::iterator sdki;
        unsigned char *hash = new unsigned char[20];
	string signature;
	uint32_t signature_length;
	uint32_t message_size;
	uint32_t fsrev = htonl(mFsRev);

	assert( sizeof(uint32_t) == 4);

#ifdef DEBUGOUTPUT
	cerr << "File System Revision is: " << mFsRev << endl;
#endif

	result.append(reinterpret_cast<const char*>(&blockID), sizeof(uint32_t));
	result.append(reinterpret_cast<const char*>(&fsrev), sizeof(uint32_t));
        result.append(reinterpret_cast<const char*>(&public_key_length), sizeof(uint32_t));
	result += mSig->GetPublicKey();
        result.append(reinterpret_cast<const char*>(&sdkeylistsize), sizeof(uint32_t));
        sdki = sdkeylist.begin();
        while ( sdki != sdkeylist.end() ) {
        	result.append(reinterpret_cast<const char*>(&(*sdki)), sizeof(cSDTreeCommon::keyEntry) - cSDTreeCommon::aes_bits/8); // we do not append the keys!
        	sdki++;
        }
        GenerateEncryptedCoverKeys(coverKeyList);
	//memset(coverKeyList, 0, sizeof(keyEntry));
#ifdef DEBUGOUTPUT
	cerr << "CoverKeyListStart: " << result.size() << endl;
	cerr << "Key: " << cSDTreeCommon::CharToHex(coverKeyList[0].key, 16) << endl;
#endif
	result.append(reinterpret_cast<const char*>(coverKeyList), sizeof(cSDTreeCommon::coverKey)*sdkeylist.size());
#ifdef DEBUGOUTPUT
	cerr << "CoverKeyListEnd: " << result.size() << endl;

	cerr << "Encrypted Message size: " << message.size() << endl;
#endif
	message_size = message.size() + cSDTreeCommon::aes_bits/8; // hinter dem + kommt die l�nge des IV
	message_size = htonl(message_size);
	result.append(reinterpret_cast<const char*>(&message_size), sizeof(uint32_t));
	result.append(reinterpret_cast<const char*>(aesmasterkeyiv), cSDTreeCommon::aes_bits/8);
	result += cSDTreeCommon::AESEncryptMessage(message, aesmasterkey, aesmasterkeyiv);

#ifdef DEBUGOUTPUT
	cerr << "Hashlength: " << result.length() << endl;
#endif
        cSDTreeCommon::SHA1Hash(result.c_str(), result.size(), hash);
#ifdef DEBUGOUTPUT
	cerr << "Hash: " << cSDTreeCommon::CharToHex(hash, 20) << endl;
#endif
        mSig->SignSHA1Hash(hash);
	signature = mSig->GetSignature();
	signature_length = signature.size();
	signature_length = htonl(signature_length);

	result.append(reinterpret_cast<const char*>(&signature_length), sizeof(uint32_t));
	result += signature;
#ifdef DEBUGOUTPUT
	cerr << "Siglen: " << signature_length << endl;
#endif

	//cout << result;
	//mFsMRev++;

        delete[] coverKeyList;
        delete[] hash;
       	return result;
}

/**
 * Write the client data to an output stream. Client data contains our public key and
 * all the keys a client needs to decrypt data.
 *
 * \param stream output stream to output data to
 */
void cFPublish::WriteClientData(ostream &stream)
{
	uint32_t public_key_length = mSig->GetPublicKeyLength();
	stream.write(reinterpret_cast<const char*>(&public_key_length), sizeof(uint32_t));
	stream << mSig->GetPublicKey();
	stream.write(reinterpret_cast<const char*>(&ourPath), sizeof(tPath));
	stream.write(reinterpret_cast<const char*>(keylist), sizeof(cSDTreeCommon::keyEntry)*num_keys);
}

/**
 * Write the client data to a file. Client data contains our public key and
 * all the keys a client needs to decrypt data.
 *
 * \param path filename to output data to
 */
void cFPublish::WriteClientData(const string &path)
{
	ofstream outfile;
	outfile.open(path.c_str());
	WriteClientData(outfile);
	outfile.close();
}

/**
 * Write the server data to an output stream. Server data contains things like our private key and
 * all the revoced paths.
 *
 * \param stream output stream to output data to
 */
void cFPublish::WriteServerData(ostream &stream)
{
	uint32_t private_key_length;
	string private_key;
	uint32_t revocelistlength = revokelist.size();
	set<tDPath>::iterator revocelist_iter;
	uint32_t treesecret_length;

    private_key = mSig->GetPrivateKey();
	private_key_length = private_key.length();
	treesecret_length = mTreeSecret.length();

#ifdef DEBUGOUTPUT
	cout << "Private key length is " << private_key_length << endl;
#endif
	stream.write(reinterpret_cast<const char*>(&private_key_length), sizeof(uint32_t));
	stream << private_key;
	stream.write(reinterpret_cast<const char*>(&treesecret_length), sizeof(uint32_t));
	stream << mTreeSecret;
	stream.write(reinterpret_cast<const char*>(&mFsRev), sizeof(uint32_t));
#ifdef DEBUGOUTPUT
	cout << "New Filesystem Major revision is " << mFsRev << endl;
#endif
	stream.write(reinterpret_cast<const char*>(&revocelistlength), sizeof(uint32_t));
#ifdef DEBUGOUTPUT
	cout << "Revocation list length is " << revocelistlength << endl;
#endif
	for (revocelist_iter = revokelist.begin(); revocelist_iter != revokelist.end(); revocelist_iter++)
	{
		stream.write(reinterpret_cast<const char*>(&(*revocelist_iter)), sizeof(tDPath));
	}
	stream.write(reinterpret_cast<const char*>(aesmasterkey), cSDTreeCommon::aes_bits/8);
	stream.write(reinterpret_cast<const char*>(&revokelistInverted), sizeof(bool));
}

/**
 * Write the server data to a file. Server data contains things like our private key and
 * all the revoced paths.
 *
 * \param path filename to output data to
 */
void cFPublish::WriteServerData(const string &path)
{
	ofstream outfile;
	outfile.open(path.c_str());
	WriteServerData(outfile);
	outfile.close();
}

/**
 * Revoce a user and increase Filesystem revision number
 *
 * \patam rPath path to revoce
 */
void cFPublish::RevokeUser(const tDPath rPath)
{

	// ok, but this was not all. it could be, that our new inserted path is covering something, that already is in our tree.
	// if this is the case, we have got a problem, cause the generate cover algorithm will allow some users that shouldn't be allowed.
	// because of this, we have to test if some paths are covered :(
	// first let's test if our layer is < 32; if it isn't, we have got no problem

	int layer = cSDTreeCommon::GetLayer( rPath );
	/*if (layer >= 32 ) {
		return;
	} */

	// if we are still alive here, we are out of luck and really have got to do something :(
	// but nevermind
	// the first step is to find nodes, where the prefix of the path is the same as with our new paths.
	// if we have found such a path, it probably is covered by the new path.
	// and to be able to do this, we first have to generate a mask that is "1" in all places that ``count''
	// and 0 in all places that don't.

	tDPath mask = 0x0LL;
	for ( int i = 0; i < layer; i++) {
		mask |= 0x3LL << (((32-i)*2)-2);  // we shift the mask 11 to the right place :)
	}

	// ok, now let's iterate through all our items...
	set <tDPath>::iterator revoceiter = revokelist.begin();
	tDPath comparepath = mask & rPath;
	while( revoceiter != revokelist.end() ) {
		tDPath second = *revoceiter;
		if ( second >= rPath ) {
			// this cannot be part of our cover; everything that is part of our cover
			// is smaller than us. we are finished!
			break;
		}

		if (( comparepath ^ (second & mask) ) == 0x0LL) { // yay, this one is covered by us!
#ifdef DEBUGOUTPUT
			cout << cSDTreeCommon::DoublePathToString(second) << "is covered by new revoced node; removed." << endl;
#endif
			set<tDPath>::iterator deleteiter = revoceiter++;
			revokelist.erase(deleteiter);
		} else {
			revoceiter++;
		}
	}

	// in the rest of the nodes there could be one, that covers the node that was just inserted...
	while ( revoceiter != revokelist.end() ) {
		tDPath newpath = *revoceiter;
		int nlayer = cSDTreeCommon::GetLayer( newpath );
		tDPath nmask = 0x0LL;

		for ( int i = 0; i < nlayer; i++) {
			nmask |= 0x3LL << (((32-i)*2)-2);  // we shift the mask 11 to the right place :)
		}

		if ( (( newpath & nmask ) ^ ( rPath & nmask )) == 0x0LL) { // covered again
#ifdef DEBUGOUTPUT
			cout << "Our new path is already covered by " <<  cSDTreeCommon::DoublePathToString(newpath) << " aborting" << endl;
#endif
			return;
		}

		revoceiter++;
	}

	mFsRev++;
	// New aes master key!
	InitAESMasterKey();
	InitAESMasterKeyIv();
	revokelist.insert(rPath);


}

/**
 * this function takes revokelist and returns an inverted variant of it.
 *
 * Example:
 * if we have a revoke list like
 * 0001
 * and want to invert it, we have to revoke
 * 1*
 * 01*
 * 001*
 * 0000
 */
std::set<tDPath> cFPublish::GetInvertedRevokelist() {
	assert(revokelist.size() > 0);
	
	set<tDPath>::iterator reviter;
	set<tDPath>::iterator newiter;
	
	reviter = revokelist.begin();
	
	set<tDPath> newlist;
	
	tDPath allcover = 0x1LL << ((2* ( 32 ) )-1);
	
	newlist.insert(allcover);

#ifdef DEBUGOUTPUT
	cerr << "Inserting first entry into revokelist: " << cSDTreeCommon::DoublePathToString(allcover) << endl;
#endif

	while ( reviter != revokelist.end() ) {
		// ok, now we have to test if this entry is currently revoked
		tDPath currentry = *reviter;
		
		newiter = newlist.begin();
				
		while (newiter != newlist.end() ) {
			tDPath second = *newiter;
			//cout << "Second    " << cSDTreeCommon::DoublePathToString(second) << endl;
			//cout << "Currentry " << cSDTreeCommon::DoublePathToString(currentry) << endl;

			if ( currentry >= second ) {
				// this cannot be part of our cover; everything that is part of our cover
				// is smaller than us. we are finished!
				newiter++;
				continue;
			}
					
			int currlayer = cSDTreeCommon::GetLayer( second );
			tDPath mask = 0x0LL;
			for ( int i = 0; i < currlayer; i++) {
				mask |= 0x3LL << (((32-i)*2)-2);  // we shift the mask 11 to the right place :)
			}
			
			if ( (( second & mask ) ^ ( currentry & mask )) == 0x0LL) { // covered.
#ifdef DEBUGOUTPUT
				//cout << "Mask      " <<  cSDTreeCommon::DoublePathToString(mask) << endl;
				//cout << "Second    " << cSDTreeCommon::DoublePathToString(second) << endl;
				//cout << "Currentry " << cSDTreeCommon::DoublePathToString(currentry) << endl;
				cerr << "The allowed entry " << cSDTreeCommon::DoublePathToString(currentry) << " is covered by " <<  cSDTreeCommon::DoublePathToString(second) << "; Layer: " << currlayer << endl;
#endif
				newlist.erase(newiter);
				//tDPath baseentry = second & mask; // only leave the interesting stuff.
				//baseentry = baseentry ^ (0x1LL << ((2* ( 32 - currlayer) )-1)); // kill the I-am-covering-bit of the layer.
				
				for ( int j = currlayer+1; j < cSDTreeCommon::GetLayer(currentry) ; j++ ) {
					
					tDPath newmask = 0x0LL; // the mask which covers the path.
					for ( int t = 0; t < j; t++) {
						newmask |= 0x7LL << (((32-t)*2)-3);  // we shift the mask 11 to the right place :)
					}
					
					//tDPath pathmask = newmask << 1; // this mask covers the path minus the last element. the last element has to be the one which is switched in comparison to
					
					// create covering entry for each lower layer.
					//tDPath createentry = (baseentry ^ currentry) & newmask;
									   //& (currentry & ( newmask << 1 ));
					
					tDPath createentry = currentry ^ (0x3LL << ((2* ( 32 - j) )-1)); // cover that part of the tree and invert the path just before
					createentry &= newmask; // & kill the uninteresting stuff;
					
					//createentry &= 0x5555555555555555LL;
					//createentry |= (0x1LL << ((2* ( 32 - j) )-1));

#ifdef DEBUGOUTPUT
					//cout << "Newmask  " << cSDTreeCommon::DoublePathToString(newmask) << endl;
					cerr << "Revoking " << cSDTreeCommon::DoublePathToString(createentry) << endl;
#endif
					newlist.insert(createentry);
					
				}
				
				newiter = newlist.begin();
				continue;
				
			}
			
			newiter++;
			
		}
		
		reviter++;
	}
	
	return newlist;	
}

/**
 *  ok, this function could be a little difficult to understand...
 *  usually we have got a 32 bit path. we expand this path to 64 bit to be able to mark
 *  regions of the tree that are covered by this mode. By using a 64 bit key we should be able to
 *  use simple binary calculations to calculate our subset differences :)
 *
 *  this function damages revocelist. Do not write the server data back to a file after
 *  calling GenerateCover.
 *
 * \todo perhaps copy revocelist beforehand (but that creates overhead)
 */
void cFPublish::GenerateCover()
{
	if ( revokelistInverted && (!revokelistInvertedInMemory) ) {
		revokelist = GetInvertedRevokelist();
		revokelistInvertedInMemory = true;
	}
	
	if ( revokelist.size() == 0 ) {
		cerr << "Revocation list has to have at least one element!" << endl;
		exit(-1);
	}
	
	//tDPath allone = 0;
	set<tDPath>::iterator reviter;

	// stupid idea.
	//for(int i = 0; i < 64; i++) {
	//	allone |= (tDPath) 1 << i;
	//}
	//cout << cSDTreeCommon::DoublePathToString(allone) << endl;

	reviter = revokelist.begin();

	while( std::distance(reviter, revokelist.end() ) >= 2)
	{
		set<tDPath>::iterator out_element_1_iterator = reviter; // iterator to the first element of out
		tDPath out = (~(*reviter)) & (*(++reviter));
		set<tDPath>::iterator out_element_2_iterator = reviter; // iterator to the second element out out
		tDPath out2 = 0x0L;

		if ( reviter != revokelist.end() )
		{
			out2 = (~(*reviter)) & (*(++reviter));
		}

		//cout << out << " out2 " << out2 << endl;
		if ( (out <= out2) || ( revokelist.size() == 2) )
		{
			// if this is true, the second pair of nodes covers a bigger set of the tree than the first set of nodes
			// and that means (at least in my opinion) that it is not possible that there is another node between the ones of the first set
			// hence we should be able to operate on them...
			// so let's get on with it and let's unite them
			// the iterator should be out of the way and we may modify a stl::set with an active iterator, without the iterator becoming invalid
			// (but the iterator must not point to an element that is removed)

			// now let's find out if we have to generate a new subset difference for one of our two elements...
			// (we need to create a new subset difference, if the height-difference between the node and the covering
			// node is > 1; for the details please refer to "Revocation and Tracing Schemes for Stateless Revievers" p.11)

			int cover_layer = cSDTreeCommon::GetLayer( out << 1 );
			int element_1_layer = cSDTreeCommon::GetLayer( *out_element_1_iterator );
			int element_2_layer = cSDTreeCommon::GetLayer( *out_element_2_iterator );

#ifdef DEBUGOUTPUT
			cerr << "Layer of Element 1 is " << element_1_layer << "; layer of Element 2 is " << element_2_layer << endl;
			cerr << "Element 1:" << cSDTreeCommon::DoublePathToString(*out_element_1_iterator) << endl;
			cerr << "Element 2:" << cSDTreeCommon::DoublePathToString(*out_element_2_iterator) << endl;
			cerr << "Cover: " << cSDTreeCommon::DoublePathToString( out << 1) << endl;

			cerr << "Covering Layer is " << cover_layer << endl;
#endif

			if ( cover_layer > element_2_layer ) // special case: element 1 is a part of element 2. solution: kill element 1 and forget about it.
			{
				/*
#ifdef DEBUGOUTPUT
				cerr << "Element 1 is a part of element 2... deleting and aborting" << endl;
#endif
				revocelist.erase(out_element_1_iterator);
				reviter--;
				continue; */
				// this case now should never occur, because the revoceUser function prohibits it; if something like this
				// occurs, panik!
				assert(false);
			}

			if ( element_1_layer - cover_layer > 1)
			{
				cSDTreeCommon::keyEntry newentry;
				newentry.subsetdepth = cover_layer + 1;
				newentry.differencedepth = element_1_layer;
				newentry.path = cSDTreeCommon::DoublePathToPath(*out_element_1_iterator);
				GetCenterKey(&newentry);
				sdkeylist.push_back(newentry);
			}


			if ( element_2_layer - cover_layer > 1)
			{
				cSDTreeCommon::keyEntry newentry;
				newentry.subsetdepth = cover_layer + 1;
				newentry.differencedepth = element_2_layer;
				newentry.path = cSDTreeCommon::DoublePathToPath(*out_element_2_iterator);
				GetCenterKey(&newentry);
				sdkeylist.push_back(newentry);
			}

			// ok, now that we know that we will combine these two elements, we can remove them from the set...
			// but we save the first one ( we will need it a few lines later)
			tDPath prefix = *out_element_1_iterator;
			revokelist.erase(out_element_1_iterator);
			revokelist.erase(out_element_2_iterator);
			// and we have to insert a new path that covers the elements that we just removed...
			revokelist.insert( prefix | ( out << 1 ) );

			reviter--;
			if ( revokelist.size() == 2 ) {
				reviter = revokelist.begin();
			}

		} else {
			// now in this case the second pair covers a smaller part of the tree than the first one...
			// there is the (distinct) possibility, that the next nodes cover a even smaller part of the tree...
			// that means we move the iterator one step back (we moved it two steps forward in the beginning) and try again in the next loop
			reviter--;
		}

		//cout << "Distanceenend: " << std::distance(reviter, revocelist.end())  << endl;
		//cout << "Sizeend: " << revocelist.size() << endl;
	}

	// and the last element
	if (revokelist.size() == 1)
	{
		if ( ! (  (*(revokelist.begin())) & 0x8000000000000000LL ) ) {
			// if the highest bit of the tree is set the entire tree already is covered. If if is not set we have to generate another entry
			cSDTreeCommon::keyEntry newentry;
			newentry.subsetdepth = 0;
			newentry.differencedepth = cSDTreeCommon::GetLayer(*(revokelist.begin()));
			newentry.path = cSDTreeCommon::DoublePathToPath(*(revokelist.begin()));
			GetCenterKey(&newentry);
			sdkeylist.push_back(newentry);
		}
	}
	
#ifdef DEBUGOUTPUT
	cerr << "New revoke list size is " << revokelist.size() << endl;
#endif
	
}

/**
 * function takes sdkeylist and generates a list of encrypted master keys in the same order.
 * we assume the length of coverKeyList to be the same as the length of sdkeylist.
 *
 * \param coverKeyList the list containing the cover keys
 */
void cFPublish::GenerateEncryptedCoverKeys(cSDTreeCommon::coverKey* coverKeyList) {
	vector<cSDTreeCommon::keyEntry>::iterator sdkeylist_iter;
	int counter = 0;

	sdkeylist_iter = sdkeylist.begin();
	while (sdkeylist_iter != sdkeylist.end() )
	{
#ifdef DEBUGOUTPUT
		string keyvalue = cSDTreeCommon::CharToHex(aesmasterkey, cSDTreeCommon::aes_bits/(8*sizeof(char)));
		cerr << "AES Master Key value: " << keyvalue << endl;
#endif
		cSDTreeCommon::AESEncryptKey(aesmasterkey, (*sdkeylist_iter).key, coverKeyList[counter].key);
		sdkeylist_iter++;
		//memcpy(coverKeyList[counter].key, aesmasterkey, 16);
#ifdef DEBUGOUTPUT
		keyvalue = cSDTreeCommon::CharToHex(coverKeyList[counter].key, cSDTreeCommon::aes_bits/(8*sizeof(char)));
		cerr << "AES Encryped Key value: " << keyvalue << endl;
#endif
		counter++;
	}
}


/**
 * get the current status of the revoke list invertion. false -> list contains revoked node.
 * true -> list contains nodes which may read the data
 */

bool cFPublish::GetRevokelistInverted() {
	return revokelistInverted;
}

/**
 * set the current status of the revoke list invertion. See GetRevokelistInverted
 */
void cFPublish::SetRevokelistInverted(const bool status) {
	revokelistInverted = status;
}

/**
 * clear all revoked users
 */
void cFPublish::ClearRevokedUsers() {
	revokelistInvertedInMemory = false;
	revokelist.clear();
}

/** @} */
