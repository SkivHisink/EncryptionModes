#include "CryptInterface.h"

namespace
{
	size_t fact(size_t n)
	{
		return (n == 0) || (n == 1) ? 1 : n * fact(n - 1);
	}

	void find_partition_numb_and_size(const size_t data_length, size_t& partition_number, size_t& partition_size)
	{
		if (data_length > 1)
			for (size_t i = 10; i > 0; --i)
			{
				if (static_cast<double>(data_length) / partition_number > 2.0)
				{
					partition_size = data_length / partition_number;
					if (data_length % partition_number != 0)
					{
						++partition_number;
						if (partition_size * partition_number < data_length)
						{
							find_partition_numb_and_size(data_length, partition_number, partition_size);
						}
					}
					break;
				}
				partition_number /= i;
			}
		else {
			partition_number = 1;
			partition_size = 1;
		}
	}
}

bool CryptInterface::is_valid(const std::string& data, const std::string& result) const
{
	if (data.size() == 0 || result.size() == 0 || strategy_ == nullptr) {
		return false;
	}
	return true;
}

bool CryptInterface::encpypt_data(const std::string& data, std::string& result) const
{
	if (!is_valid(data, result)) {
		return false;
	}
	const size_t length = data.length();
	std::string encr_result;
	size_t partition_number = fact(10);
	size_t partition_size = 0;
	find_partition_numb_and_size(length, partition_number, partition_size);
	strategy_->initial_vector_gen(partition_size);
	//initialization
	for (size_t i = 0; i < partition_size; ++i) {
		strategy_->encrypt_init(encr_result, data[i], i);
	}
	for (size_t j = 1; j < partition_number; ++j) {
		for (size_t i = j * partition_size; i < (j + 1) * partition_size; ++i) {
			strategy_->encrypt(encr_result, data, i, partition_size);//procedure of encryption
		}
	}
	result = encr_result;
	return true;
}

bool CryptInterface::decrypt_data(const std::string& data, std::string& result) const
{
	if (!is_valid(data, result)) {
		return false;
	}
	size_t length = data.length();
	size_t partition_number = fact(10);
	size_t partition_size = 0;
	find_partition_numb_and_size(length, partition_number, partition_size);
	if (!strategy_->get_initial_vector().empty() && partition_size != strategy_->get_initial_vector().size() - 1)
	{
		partition_size = strategy_->get_initial_vector().size() - 1;
		partition_number = length / partition_size;
	}
	std::string decrypt_result;
	//initialization
	for (size_t i = 0; i < partition_size; ++i) {
		strategy_->decrypt_init(decrypt_result, data[i], i);
	}
	for (size_t j = 1; j < partition_number; ++j) {
		for (size_t i = j * partition_size; i < (j + 1) * partition_size; ++i) {
			strategy_->decrypt(decrypt_result, data, i, partition_size);
		}
	}
	result = decrypt_result;
	return true;
}