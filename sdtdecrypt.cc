// This is a little test program that decrypts a file that has been encrypted
// with the subset difference encryption scheme.
// File uses "cfile" for its client keys and tries to decrypt the data present
// in the file named "rev".
//
// Johanna Amann <johanna@0xxon.net>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <string>
#include <fstream>
#include <unistd.h>

#include "fclient.hh"

using namespace std;

/**
 * get the file size of the file named name
 *
 * \param name - filename
 * \return file size
 */
long getfilesize(string name) {
 	long begin,end;
 	ifstream myfile (name.c_str());
 	begin = myfile.tellg();
  	myfile.seekg (0, ios::end);
  	end = myfile.tellg();
  	myfile.close();
	return (end-begin);
}

/**
 * The main function of our little test program; this should be pretty self-explicatory,
 * we just parse the command line options and use a few simple modules, depending on the
 * given options
 */
int main (int argc, char **argv)
{
	char c;
	bool verbose = false;
	ifstream revfile;
	string revdata;
	long filesize;
	unsigned char *revbuf;
	cFClient* client;
	string cfile = "./cfile";
	string revfilename = "./rev";

	string usage = \
	" c: client key file\n" \
	" r: encrypted data file\n" \
	" v: be verbose\n\n";

	while (( c = getopt(argc, argv, "c:?hvr:")) != -1 ) {
		switch(c) {
			case 'c':
				cfile = optarg;
				break;
			case 'r':
				revfilename = optarg;
				break;
			case 'v':
				verbose = true;
				break;
			case 'h':
			case '?':
				std::cout << "Help: \n\n" << usage << endl;
				return 0;
				break;
		}
	}

	filesize = getfilesize(revfilename);
  	if ( verbose )
		cout << "size is: " << filesize << " bytes.\n";
	revbuf = new unsigned char[filesize];

	try {
		client = new cFClient(cfile);
	} catch (cSDTreeCommon::ClientException e) {
		cerr << "Error: " << e.getMessage() << endl;
		exit(2);
	}

	revfile.open(revfilename.c_str(), ios::binary);
	assert(revfile.is_open());
	revfile.read(reinterpret_cast<char*>(revbuf), filesize);
	revfile.close();

	revdata.assign(reinterpret_cast<const char*>(revbuf), filesize);

	if ( verbose ) {
		client->PrintECInformation();
		client->PrintKeylist();
	}

	try {
		if ( verbose ) {
			cout << "Decrypted data: " << client->Decrypt(revdata) << endl;
		} else {
			cout << client->Decrypt(revdata) << flush;
		}
	} catch (cSDTreeCommon::ClientException e) {
		cout << "Error while decrypting: ";
		cout << e.getMessage() << endl;
		exit(1);
	}
	delete client;
	delete[] revbuf;
}

/** @} */
