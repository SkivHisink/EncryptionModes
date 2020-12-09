#include "pch.h"

#include "CryptInterface.h"
#include "CipherBlockChaining.h"
#include "ElectronicCodebook.h"
#include "OutputFeedback.h"

class MemoryLeaksTests : public testing::Test
{
protected:
	void SetUp() override
	{
		_CrtMemCheckpoint(&startup_);
	}

	void TearDown() override
	{
		_CrtMemState teardown, diff;
		_CrtMemCheckpoint(&teardown);
		ASSERT_EQ(0, _CrtMemDifference(&diff, &startup_, &teardown)) << "Memory leaks detected";
	}
	_CrtMemState startup_ = {};
};

char encryption_procedure(char encr_result, char key)
{
	return encr_result ^ key;
}

char decryption_produce(char decr_result, char key)
{
	return decr_result ^ key;
}

TEST(TestCaseName, TestName) {
	EXPECT_EQ(1, 1);
	EXPECT_TRUE(true);
}

struct CBC :MemoryLeaksTests {};

TEST_F(CBC, SmallTextTest)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	CryptInterface crypt_interface(std::make_shared<CipherBlockChaining>(enc, dec));
	std::string input = "R";
	std::string encrypted_cbe = input;
	std::string decrypted_cbe = input;
	if (crypt_interface.encpypt_data(input, encrypted_cbe))
		crypt_interface.decrypt_data(encrypted_cbe, decrypted_cbe);
	EXPECT_STREQ(input.c_str(), decrypted_cbe.c_str());
}

TEST_F(CBC, SimpleTextTest)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	CryptInterface crypt_interface(std::make_shared<CipherBlockChaining>(enc, dec));
	std::string input = "Reality cuts me like a knife";
	std::string encrypted_cbc = input;
	std::string decrypted_cbc = input;
	if (crypt_interface.encpypt_data(input, encrypted_cbc)) {
		crypt_interface.decrypt_data(encrypted_cbc, decrypted_cbc);
	}
	EXPECT_STREQ(input.c_str(), decrypted_cbc.c_str());
}

TEST_F(CBC, EmptyInputString)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	CryptInterface crypt_interface(std::make_shared<CipherBlockChaining>(enc, dec));
	std::string input = "";
	std::string encrypted_cbc = input;
	std::string decrypted_cbc = input;
	bool encpypt_valid = crypt_interface.encpypt_data(input.c_str(), encrypted_cbc);
	EXPECT_FALSE(encpypt_valid);
}

struct ECB :MemoryLeaksTests {};

TEST_F(ECB, SmallTextTest)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	CryptInterface crypt_interface(std::make_shared<ElectronicCodebook>(enc, dec));
	std::string input = "R";
	std::string encrypted_cbe = input;
	std::string decrypted_cbe = input;
	if (crypt_interface.encpypt_data(input, encrypted_cbe))
		crypt_interface.decrypt_data(encrypted_cbe, decrypted_cbe);
	EXPECT_STREQ(input.c_str(), decrypted_cbe.c_str());
}


TEST_F(ECB, SimpleTextTest)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	CryptInterface crypt_interface(std::make_shared<ElectronicCodebook>(enc, dec));
	std::string input = "QWERTY qwerty QwErTy qWeRt";
	std::string encrypted_cbe = input;
	std::string decrypted_cbe = input;
	bool valid = crypt_interface.encpypt_data(input, encrypted_cbe);
	EXPECT_TRUE(valid);
	if (valid) {
		valid = crypt_interface.decrypt_data(encrypted_cbe, decrypted_cbe);
		EXPECT_TRUE(valid);
	}
	EXPECT_STREQ(input.c_str(), decrypted_cbe.c_str());
}

TEST_F(ECB, EmptyInputString)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	CryptInterface crypt_interface(std::make_shared<ElectronicCodebook>(enc, dec));
	std::string input = "";
	std::string encrypted_cbe = input;
	std::string decrypted_cbe = input;
	bool encpypt_valid = crypt_interface.encpypt_data(input.c_str(), encrypted_cbe);
	EXPECT_FALSE(encpypt_valid);
	if (encpypt_valid)
		crypt_interface.decrypt_data(encrypted_cbe, decrypted_cbe);
}

struct OFB :MemoryLeaksTests {};

TEST_F(OFB, SmallTextTest)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	CryptInterface crypt_interface(std::make_shared<OutputFeedback>(enc, dec));
	std::string input = "R";
	std::string encrypted_ofb = input;
	std::string decrypted_ofb = input;
	if (crypt_interface.encpypt_data(input, encrypted_ofb))
		crypt_interface.decrypt_data(encrypted_ofb, decrypted_ofb);
	EXPECT_STREQ(input.c_str(), decrypted_ofb.c_str());
}


TEST_F(OFB, SimpleTextTest)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	CryptInterface crypt_interface(std::make_shared<OutputFeedback>(enc, dec));
	std::string input = "QWERTY qwerty QwErTy qWeRtY";
	std::string encrypted_ofb = input;
	std::string decrypted_ofb = input;
	if (crypt_interface.encpypt_data(input.c_str(), encrypted_ofb))
		crypt_interface.decrypt_data(encrypted_ofb, decrypted_ofb);
	EXPECT_STREQ(input.c_str(), decrypted_ofb.c_str());
}

TEST_F(OFB, EmptyInputString)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	CryptInterface crypt_interface(std::make_shared<OutputFeedback>(enc, dec));
	std::string input = "";
	std::string encrypted_ofb = input;
	bool encpypt_valid = crypt_interface.encpypt_data(input, encrypted_ofb);
	EXPECT_FALSE(encpypt_valid);
}

TEST_F(OFB, EmptyEncryptorDecryptor)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	EXPECT_THROW(CryptInterface crypt_interface(std::make_shared<OutputFeedback>(nullptr, dec)), BadFunctionException);
	EXPECT_THROW(CryptInterface crypt_interface(std::make_shared<OutputFeedback>(enc, nullptr)), BadFunctionException);
	EXPECT_THROW(CryptInterface crypt_interface(std::make_shared<OutputFeedback>(nullptr, nullptr)), BadFunctionException);
}

struct Strategy_encryption :MemoryLeaksTests {};

TEST_F(Strategy_encryption, CBC_ECB_strategyChanging)
{
	std::function<char(char, char)> enc = encryption_procedure;
	std::function<char(char, char)> dec = decryption_produce;
	std::string input = "Strategy changing test";
	std::string encrypted_cbc = input;
	std::string encrypted_ofb = input;
	std::string decrypted_cbc = input;
	std::string decrypted_ofb = input;
	CryptInterface crypt_interface(std::make_shared<OutputFeedback>(enc, dec));
	bool valid = crypt_interface.encpypt_data(input, encrypted_ofb);
	EXPECT_TRUE(valid);
	if (valid) {
		valid = crypt_interface.decrypt_data(encrypted_ofb, decrypted_ofb);
		EXPECT_TRUE(valid);
	}
	EXPECT_STREQ(input.c_str(), decrypted_ofb.c_str());
	crypt_interface.set_strategy(std::make_shared<CipherBlockChaining>(enc, dec));
	valid = crypt_interface.encpypt_data(input, encrypted_cbc);
	EXPECT_TRUE(valid);
	if (valid) {
		valid = crypt_interface.decrypt_data(encrypted_cbc, decrypted_cbc);
		EXPECT_TRUE(valid);
	}
	EXPECT_STREQ(input.c_str(), decrypted_cbc.c_str());
}
