#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#include <string>
#include "CryptInterface.h"
#include "CipherBlockChaining.h"
#include "ElectronicCodebook.h"
#include "OutputFeedback.h"

char encryption_procedure(char encr_result, char key)
{
	return encr_result ^ key;
}

char decryption_produce(char decr_result, char key)
{
	return decr_result ^ key;
}

int main()
{
	{
		std::function<char(char, char)> enc = encryption_procedure;
		std::function<char(char, char)> dec = decryption_produce;
		std::string input = "Hello world!";
		//CBC
		CryptInterface crypt_interface(new CipherBlockChaining(enc, dec));
		std::string encrypted_cbc=input;
		std::string decrypted_cbc = input;
		if (crypt_interface.encpypt_data(input, encrypted_cbc))
			crypt_interface.decrypt_data(encrypted_cbc, decrypted_cbc);
		//ECB
		crypt_interface.set_strategy(new ElectronicCodebook(enc, dec));
		std::string encrypted_ecb = input;
		std::string decrypted_ecb = input;
		if (crypt_interface.encpypt_data(input, encrypted_ecb))
			crypt_interface.decrypt_data(encrypted_ecb, decrypted_ecb);
		//OFB
		crypt_interface.set_strategy(new OutputFeedback(enc, dec));
		std::string encrypted_ofb = input;
		std::string decrypted_ofb = input;
		if (crypt_interface.encpypt_data(input, encrypted_ofb))
			crypt_interface.decrypt_data(encrypted_ofb, decrypted_ofb);
		//Check results
		if (input.compare(decrypted_cbc))
		{
			std::cout << "Bad Cipher Block Chaining encryption" << std::endl;
		}
		if (input.compare(decrypted_ecb))
		{
			std::cout << "Bad Electronic Codebook encryption" << std::endl;
		}
		if (input.compare(decrypted_ofb))
		{
			std::cout << "Bad Output Feedback encryption" << std::endl;
		}
	}
	if (_CrtDumpMemoryLeaks() != 0)
	{
		std::cout << "Memory leaks founded!" << std::endl;
	}
	return 0;
}