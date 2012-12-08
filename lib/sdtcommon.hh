// stuff that is needed by nearly everything that handles the Subset Difference Algorithm
//
// Johanna Amann <johanna@0xxon.net>

#ifndef SDTCOMMON_HH_
#define SDTCOMMON_HH_

#include <string>
#include <stdint.h>

typedef uint32_t tPath;
typedef uint64_t tDPath;

/**
 * Stuff that is needed by nearly everything that uses the SD-Scheme direclty
 * Perhaps some of this stuff should be used elsewhere (in cSignature or in cSdtKeyList)
 */
class cSDTreeCommon
{
public:
	static const unsigned int aes_bits = 128;
	static const unsigned int tree_height = 32;

	/**
	 * Contains a path with the subset and difference and the corresponding key
	 */
	struct keyEntry {
		tPath path;
		unsigned int subsetdepth;
		unsigned int differencedepth;
		unsigned char key[aes_bits/8];
	//	unsigned char enckey[cSDTreeCommon::aes_bits/8]; bad Idea.
	};

	/**
	 * Identifies a specific Node in the tree; ATTN! Structure has to be the same as the structure of keyEntry minus key.
	 */
	struct nodeId {
		tPath path;
		unsigned int subsetdepth;
		unsigned int differencedepth;
	};

	struct coverKey {
		unsigned char key[aes_bits/8];
	};

	class Exception : public std::exception {
	public:
		Exception(const std::string &msg) : message(msg) {}
		virtual ~Exception() throw() {}
		std::string getMessage() { return message; }
	private:
		std::string message;
	};

	class ClientException : public Exception {
	public:
		ClientException(const std::string &msg) : Exception(msg) {}
	};

	class PublishException : public Exception {
	public:
		PublishException(const std::string &msg) : Exception(msg) {}
	};

	static void AESctr(const unsigned char* , unsigned char*);
	static void left(unsigned char *key);
	static void right(unsigned char *key);
	static void center(unsigned char *key);
	static std::string PathToString(const tPath path);
	static tPath StringToPath(const std::string &in);
	static tDPath StringToDoublePath(const std::string &in);
	static std::string DoublePathToString(const tDPath path);
	static std::string CharToHex(const unsigned char *m, const int size);
	//virtual void GetKeyFromPath() = 0;
	//virtual ~cSDTreeCommon() {}
	static int GetLayer(tDPath path);
	static tPath DoublePathToPath(tDPath);
	static std::string AESDecryptMessage(const std::string &message, int size, const unsigned char* aesmasterkey, unsigned char* aesmasterkeyiv);
	static std::string AESEncryptMessage(const std::string &message, const unsigned char* aesmasterkey, unsigned char* aesmasterkeyiv);
	static void AESEncryptKey(const unsigned char *ctr, const unsigned char *key, unsigned char *out);
	static void AESDecryptKey(const unsigned char *ctr, const unsigned char *key, unsigned char *out);
	static void SHA1Hash(const void *data, const int datasize, unsigned char* hash);
	static std::string SHA1Hash(const std::string &data);
	static std::string SHA256Hash(const std::string &data);

public:
	typedef void RandomBytesFunction(unsigned int number, unsigned char *bytes);

	static void SetRandomBytesFunction(RandomBytesFunction *function) { randomBytesFunction = function; }
	static void GetRandomBytes(unsigned int number, unsigned char *bytes) { return (*randomBytesFunction)(number,bytes); }

private:
	static void DefaultRandomBytesFunction(unsigned int number, unsigned char *bytes);

	static RandomBytesFunction *randomBytesFunction;
};

#endif /* SDTCOMMON_HH_ */

/** @} */
