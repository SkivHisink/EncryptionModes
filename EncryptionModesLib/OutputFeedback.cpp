#include "OutputFeedback.h"

#include <random>

std::string OutputFeedback::key_gen()
{
	std::mt19937 gen{ 0 };
	for (size_t i = 0; i < 255; ++i)
	{
		key_.push_back(gen());
	}
	key_.push_back('\0');
	return key_;
}

void OutputFeedback::decrypt_init(std::string& decrypt_result, char data, size_t i)
{
	decrypt_result.push_back(decrypt_method(key_[i % 256], initial_vector_[i]) ^ data);
}
void OutputFeedback::decrypt(std::string& decrypt_result, const std::string& data, size_t i, size_t partition_size)
{
	decrypt_result.push_back(decrypt_method(key_[i % 256], decrypt_result[i - partition_size] ^ data[i - partition_size]) ^ data[i]);
}

void OutputFeedback::encrypt_init(std::string& encr_result, char data, size_t i)
{
	encr_result.push_back(encrypt_method(key_[i % 256], initial_vector_[i]) ^ data);
}

void OutputFeedback::encrypt(std::string& encr_result, const std::string& data, size_t i, size_t partition_size)
{
	if (i < data.length()) {
		encr_result.push_back(encrypt_method(key_[i % 256], encr_result[i - partition_size] ^ data[i - partition_size]));
		encr_result[encr_result.length() - 1] = data[i] ^ encr_result[encr_result.length() - 1];//procedure of encryption
	}
	else {
		encr_result.push_back(encrypt_method(key_[i % 256], encr_result[i - partition_size] ^ data[i - partition_size])); //padding
	}
}


std::string OutputFeedback::initial_vector_gen(size_t partition_size)
{
	std::mt19937 gen{ 1 };
	for (size_t i = 0; i < partition_size; ++i)
	{
		initial_vector_.push_back(gen());
	}
	initial_vector_.push_back('\0');
	return  initial_vector_;
}
