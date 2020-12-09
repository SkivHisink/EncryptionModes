#pragma once
#include <memory>

#include "EncryptionBase.h"

class CryptInterface final
{
	bool is_valid(const std::string& data, const std::string& result) const;
	std::shared_ptr<EncryptionBase> strategy_;
public:
	explicit CryptInterface(std::shared_ptr<EncryptionBase> strategy = nullptr) : strategy_(std::move(strategy)) {}
	~CryptInterface() = default;

	void set_strategy(std::shared_ptr<EncryptionBase> strategy)
	{
		this->strategy_ = std::move(strategy);
	}

	bool encpypt_data(const std::string& data, std::string& result) const;
	bool decrypt_data(const std::string& data, std::string& result) const;

	std::string get_key()
	{
		return strategy_->get_key();
	}
	std::string get_initial_vector()
	{
		return strategy_->get_initial_vector();
	}
};
