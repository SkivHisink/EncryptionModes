#include "ElectronicCodebook.h"
#include <random>


void ElectronicCodebook::encrypt_init(std::string& encr_result, char data, size_t i)
{
	encr_result.push_back(encrypt_method(data, key_[i % 256]));//procedure of encryption
}

void ElectronicCodebook::encrypt(std::string& encr_result, const std::string& data, size_t i, size_t partition_size)
{
	if (i < data.length()) {
		encr_result.push_back(encrypt_method(data[i], key_[i % 256]));//procedure of encryption
	}
	else {
		encr_result.push_back(encrypt_method(key_[i % 256], '\0'));//padding
	}
}

void ElectronicCodebook::decrypt_init(std::string& decrypt_result, char data, size_t i)
{
	decrypt_result.push_back(decrypt_method(data, key_[i % 256]));
}

void ElectronicCodebook::decrypt(std::string& decrypt_result, const std::string& data, size_t i, size_t partition_size)
{
	decrypt_result.push_back(decrypt_method(data[i], key_[i % 256]));
}
std::string ElectronicCodebook::key_gen()
{
	std::mt19937 gen{ 0 };
	for (size_t i = 0; i < 255; ++i)
	{
		key_.push_back(gen());
	}
	key_.push_back('\0');
	return key_;
}
