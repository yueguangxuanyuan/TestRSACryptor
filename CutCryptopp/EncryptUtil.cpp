#include "EnCryptUtil.h"
#include "Common.h"
#include <hex.h>
#include <rsa.h>
#include <randpool.h>
#include <osrng.h>
#include <base64.h>
#include <iostream>
#include <sstream>
#include <algorithm>
using namespace CryptoPP;

namespace EnCryptUtil 
{
	void RemoveSpace(std::string &InputStr)
	{
		size_t Location = InputStr.find_first_of(" ");
		while ( Location != std::string::npos)
		{
			InputStr.erase(Location, 1);
			Location = InputStr.find_first_of(" ");
		}
	}

	std::string GetPublicKeyStr()
	{
		std::string PublicKey(OAEPPublicKey);
		RemoveSpace(PublicKey);
		return PublicKey;
	}

	std::string GetPrivateKeyStr()
	{
		std::string PrivateKey(OAEPPrivateKey);
		RemoveSpace(PrivateKey);
		return PrivateKey;
	}

	void LoadEncrypt(RSAES_OAEP_SHA_Encryptor &Encrypt)
	{
		std::string OAEPPublicKeyStr = GetPublicKeyStr();
		printf("before base64 :\n%s\n", OAEPPublicKeyStr.c_str());
		StringSource ss(OAEPPublicKeyStr, true, new Base64Decoder);
		Encrypt.AccessKey().Load(ss);
	}

	void LoadDecrypt(RSAES_OAEP_SHA_Decryptor &Decrypt)
	{
		std::string OAEPPrivateKeyStr = GetPrivateKeyStr();
		printf("before base64 :\n%s\n", OAEPPrivateKeyStr.c_str());
		StringSource ss(OAEPPrivateKeyStr, true, new Base64Decoder);
		Decrypt.AccessKey().Load(ss);
	}

	std::string EncryptString(std::string InputStr)
	{////
		RSAES_OAEP_SHA_Encryptor Encrypt;
		LoadEncrypt(Encrypt);

		std::string Seed = "Seed";// hard code for test
		RandomPool SeedRandomPool;
		SeedRandomPool.Put((byte *)Seed.c_str(),Seed.length());

		std::string Result;
		StringSource(InputStr.c_str(),true,new PK_EncryptorFilter(SeedRandomPool,Encrypt,new Base64Encoder(new StringSink(Result))));

		return Result;
	}

	std::string DecryptString(std::string InputStr)
	{
		RSAES_OAEP_SHA_Decryptor Decrypt;
		LoadDecrypt (Decrypt);

		RandomPool DecryptRandomPool;

		std::string Result;
		StringSource(InputStr.c_str(),true, new Base64Decoder(new PK_DecryptorFilter(DecryptRandomPool, Decrypt, new StringSink(Result))));

		return Result;
	}

	std::string EncryptLongString(std::string InputStr)
	{
		RSAES_OAEP_SHA_Encryptor Encrypt;
		LoadEncrypt(Encrypt);
		
		std::string Seed = "Seed";// hard code for test
		RandomPool SeedRandomPool;
		SeedRandomPool.Put((byte *)Seed.c_str(), Seed.length());

		std::string Result;

		int FixedMaxPlaintextLength = Encrypt.FixedMaxPlaintextLength();

		if (FixedMaxPlaintextLength > InputStr.size())
		{
			StringSource(InputStr.c_str(), true, new PK_EncryptorFilter(SeedRandomPool, Encrypt, new Base64Encoder(new StringSink(Result))));
		}
		else 
		{
			std::stringstream StrinBuf;
			StrinBuf << InputStr;

			std::string ResultCache;
			char * PlainText = new char [FixedMaxPlaintextLength + 1] ;
			while (StrinBuf.get(PlainText, FixedMaxPlaintextLength + 1)) {
				std::string Cache;
				StringSource(PlainText, true, new PK_EncryptorFilter(SeedRandomPool, Encrypt, new StringSink(Cache)));
				ResultCache += Cache;
			}
			delete[] PlainText;
			

			Base64Encoder Base64EncodeFormatter(new StringSink(Result));
			Base64EncodeFormatter.Put((byte *) ResultCache.c_str() , ResultCache.size());
			Base64EncodeFormatter.MessageEnd();
		}

		return Result;
	}

	std::string DecryptLongString(std::string InputStr)
	{
		RSAES_OAEP_SHA_Decryptor Decrypt;
		LoadDecrypt(Decrypt);

		RandomPool DecryptRandomPool;

		//printf("decode\n");
		std::string EncryptedStr;
		Base64Decoder Base64DecodeFormatter(new StringSink(EncryptedStr));
		Base64DecodeFormatter.Put((byte*)InputStr.c_str(),InputStr.size());
		Base64DecodeFormatter.MessageEnd();

		std::string Result;
		if (EncryptedStr.size() <= Decrypt.FixedCiphertextLength())
		{
			StringSource(EncryptedStr, true, new PK_DecryptorFilter(DecryptRandomPool, Decrypt, new StringSink(Result)));
		}
		else
		{
			if (EncryptedStr.size()% Decrypt.FixedCiphertextLength() != 0)
			{
				return "Error in decrypt";
			}

			int Times = EncryptedStr.size() / Decrypt.FixedCiphertextLength();
			std::string ResultCache;
			int Counter = 0;
			while (Counter  < Times) {
				std::string Cache;
				std::string PlainText = EncryptedStr.substr(Decrypt.FixedCiphertextLength() * Counter, Decrypt.FixedCiphertextLength());
				//printf("%s\n", PlainText);
				StringSource(PlainText, true, new PK_DecryptorFilter(DecryptRandomPool, Decrypt, new StringSink(Cache)));
				ResultCache += Cache;

				Counter++;
			}
			 Result = ResultCache;
		}
		return Result;
	}
}


int main() 
{
	std::string Text = "test ½ñdssdsssssssssssssssssssssssssssssssssssssssssssssssssssfffffffffffffffffffffffffffffffxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxfgbvvvvvvvvd";

	printf("original text : %s \n ", Text.c_str());

	std::string EncryptedStr = EnCryptUtil::EncryptLongString(Text);

	//std::string EncryptedStr = "A8AxWiG014njIB+dKIUOQ3TZZBDeJIHYaEitNUkvcsT16JEpDalqiiecxiy4gYbQfZshx0EfegFnn9gDUJN8bQ==";
	
	std::string DecyptedStr = EnCryptUtil::DecryptLongString(EncryptedStr);

	printf("text : %s \n ", DecyptedStr.c_str());
	return 0;
}