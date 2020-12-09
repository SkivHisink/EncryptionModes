#pragma once
#include <functional>

#include "BadFunctionException.h"

class EncryptionBase
{
protected:
	virtual std::string key_gen() = 0;
	std::string key_;
	std::string initial_vector_;
	std::function<char(char, char)> encrypt_method;
	std::function<char(char, char)> decrypt_method;
public:
	EncryptionBase(std::function<char(char, char)>& new_encrypt_method,
		std::function<char(char, char)>& new_decrypt_method)
		:encrypt_method(new_encrypt_method), decrypt_method(new_decrypt_method)
	{
		if (new_encrypt_method == nullptr || new_decrypt_method == nullptr)
		{
			throw BadFunctionException();
		}
	}
	virtual ~EncryptionBase() = default;
	EncryptionBase(const EncryptionBase&) = delete;
	EncryptionBase& operator=(const EncryptionBase&) = delete;
	EncryptionBase(EncryptionBase&&) = delete;
	EncryptionBase& operator=(EncryptionBase&&) = delete;
	virtual void encrypt_init(std::string& encr_result, char data, size_t i) = 0;
	virtual void encrypt(std::string& encr_result, const std::string& data, size_t i, size_t partition_size) = 0;
	virtual void decrypt_init(std::string& decrypt_result, char data, size_t i) = 0;
	virtual void decrypt(std::string& decrypt_result, const std::string& data, size_t i, size_t partition_size) = 0;
	virtual std::string initial_vector_gen(size_t partition_size) = 0;
	virtual std::string get_key() { return key_; }
	virtual std::string get_initial_vector() { return initial_vector_; }
};
