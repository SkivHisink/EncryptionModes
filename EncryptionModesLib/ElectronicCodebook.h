#pragma once
#include <string>
#include "EncryptionBase.h"


class ElectronicCodebook final : public EncryptionBase
{
	std::string key_gen() override;
public:
	std::string initial_vector_gen(size_t partition_size) override { return initial_vector_; }
	explicit ElectronicCodebook(std::function<char(char, char)>new_encrypt_method,
		std::function<char(char, char)>new_decrypt_method)
		:EncryptionBase(new_encrypt_method, new_decrypt_method)
	{
		key_ = key_gen();
	}
	void encrypt(std::string& encr_result, const std::string& data, size_t i, size_t partition_size) override;
	void encrypt_init(std::string& encr_result, char data, size_t i) override;
	void decrypt_init(std::string& decrypt_result, char data, size_t i) override;
	void decrypt(std::string& decrypt_result, const std::string& data, size_t i, size_t partition_size) override;
};
