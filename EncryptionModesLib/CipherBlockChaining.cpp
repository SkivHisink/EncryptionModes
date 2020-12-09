#include "CipherBlockChaining.h"
#include <random>
#include <string>

void CipherBlockChaining::decrypt_init(std::string& decrypt_result, char data, size_t i)
{
	decrypt_result.push_back(decrypt_method(data, key_[i % 256]) ^ initial_vector_[i]);
}
void CipherBlockChaining::decrypt(std::string& decrypt_result, const std::string& data, size_t i, size_t partition_size)
{
	decrypt_result.push_back(static_cast<char>(decrypt_method(data[i], key_[i % 256]) ^ data[i - partition_size]));
}

void CipherBlockChaining::encrypt_init(std::string& encr_result, char data, size_t i)
{
	encr_result.push_back(static_cast<char>(data ^ initial_vector_[i]));
	encr_result[encr_result.length() - 1] = encrypt_method(encr_result[encr_result.length() - 1], key_[(encr_result.length() - 1) % 256]);//procedure of encryption
}

void CipherBlockChaining::encrypt(std::string& encr_result, const std::string& data, size_t i, size_t partition_size)
{
	if (i < data.length()) {
		encr_result.push_back(static_cast<char>(data[i] ^ encr_result[i - partition_size]));
	}
	else {
		encr_result.push_back(static_cast<char>(encr_result[i - partition_size])); //padding
	}
	encr_result[encr_result.length() - 1] = encrypt_method(encr_result[encr_result.length() - 1], key_[(encr_result.length() - 1) % 256]);//procedure of encryption
}


std::string CipherBlockChaining::key_gen()
{
	std::mt19937 gen{ 0 };
	for (size_t i = 0; i < 255; ++i)
	{
		key_.push_back(gen());
	}
	key_.push_back('\0');
	return key_;
}

std::string CipherBlockChaining::initial_vector_gen(size_t partition_size)
{
	std::mt19937 gen{ 1 };
	for (size_t i = 0; i < partition_size; ++i)
	{
		initial_vector_.push_back(gen());
	}
	initial_vector_.push_back( '\0');
	return  initial_vector_;
}
