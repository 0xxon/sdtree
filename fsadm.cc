// This program allows access to the cFPublish class and allows the creation of a publisher
// private key and the keyfiles for the clients.
//
// Johanna Amann <johanna@0xxon.net>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "fpublish.hh"
#include "sdtcommon.hh"
#include <iostream>
#include <string>
#include <fstream>

using std::string;
using std::cout;
using std::endl;
using std::ifstream;
using std::ios;
using std::cerr;

bool FileExists(string path)
{
	ifstream file;
	file.open(path.c_str(),ifstream::in);
	file.close();
	if (file.fail())
	{
		file.clear(ios::failbit);
		return false;
	} else {
		return true;
	}
}

int main(int argc, char **argv)
{
	char c;
	string serverfile = "./serverkey";
	string clientfile = "./cfile";
	string key;
	cFPublish* fs;
	bool verbose = false;
	bool outputcdata = false;
	tPath path = 0;
	string revoce;
	string treesecret = "";
	bool revocemode = false;
	bool serverwrite = false;
	bool gcover = false;
	string encstring = "";
	unsigned int revocedepth = cSDTreeCommon::tree_height;
	bool invert = false;
	bool doNotInvert = false;

	string usage = \
	" h: display this help\n"\
	" s: server key file\n"\
	" o: client key output file\n"
	" v: verbose\n"\
	" k: key to generate client file for\n"\
	" r: key to revoke\n"\
	" d: depth at which to revoke the key\n"\
	" w: write server file\n"\
	" e: set tree secret\n"\
	" g: generate cover\n"\
	" i: invert revocelist\n"\
	" I: do not invert revocelist\n\n";

	
	while((c = getopt(argc, argv, "s:o:vk:r:d:?whg:e:Ii")) != -1) {
		switch(c) {
			case 's':
				serverfile = optarg;
				break;
			case 'o':
				clientfile = optarg;
				break;
			case 'v':
				verbose = true;
				break;
			case 'k':
				key = optarg;
				outputcdata = true;
				break;
			case 'r':
				revoce = optarg;
				revocemode = true;
				break;
			case 'd':
				revocedepth = atoi(optarg);
				assert(revocedepth != 0);
				break;
			case 'w':
				serverwrite = true;
				break;
			case 'g':
				encstring = optarg;
				gcover = true;
				break;
			case 'e':
				treesecret = optarg;
				break;
			case 'i':
				invert = true;
				break;
			case 'I':
				doNotInvert = true;
				break;
			case 'h':
			case '?':
				std::cout << "Help: \n\n" << usage << endl;
				return 0;
				break;
		}
	}

	if (FileExists(serverfile))
	{
		fs = new cFPublish(serverfile);
	} else {
		fs = new cFPublish();
	}

	if ( invert && doNotInvert ) {
		cerr << "Do not set i and I at once" << endl;
	}
	
	if ( invert ) {
		cerr << "Setting inverted flag" << endl;
		fs->SetRevokelistInverted(true);
	}
	
	if ( doNotInvert ) {
		cerr << "Removing inverted flag (if set)" << endl;
		fs->SetRevokelistInverted(false);
	}	
	
	if (verbose)
	{
		fs->PrintECInformation();
	}

	if ( treesecret != "") {
		fs->SetTreeSecret(treesecret);
	}

	if (gcover) {
		fs->GenerateCover();
		if (verbose) {
			fs->PrintSDKeyList();
		}
                cout << fs->GenerateSDTreeBlock(encstring);
	}

	if (revocemode) {
		if (revoce.length() != cSDTreeCommon::tree_height) {
			cerr << "Wrong key length" << endl;
			return -1;
		}
		tDPath revocepath = cSDTreeCommon::StringToDoublePath(revoce);
		if ( revocedepth < 32 ) {
			revocepath |= 0x1LL << ((2* ( 32 - revocedepth) )-1);
		}
		cout << "Revoking " << cSDTreeCommon::DoublePathToString(revocepath) << endl;
		fs->RevokeUser(revocepath);
	}

	if (outputcdata) {
		if (key.length() != cSDTreeCommon::tree_height)
		{
			cerr << "Wrong key length" << endl;
			return -1;
		}
		path = cSDTreeCommon::StringToPath(key);
		fs->generate_keylist(path);
		if (verbose)
		{
			fs->PrintKeylist();
		}
		fs->WriteClientData(clientfile);
	}

	if (serverwrite) {
		assert(gcover == false);
		fs->WriteServerData(serverfile);
	}
		
	delete fs;
	return 0;
}

/** @} */
