#define _CRT_SECURE_NO_WARNINGS

#include "GenerateKey.h"

#include <osrng.h>
#include <base64.h>
#include <hex.h>
#include <rsa.h>
#include <files.h>
#include <sstream>
#include "base64.h"

using namespace CryptoPP;

namespace GenerateKey
{
	const unsigned char *  RemoveFirstZeroByte(const char * InputArray , size_t Length)
	{
		//const unsigned char * 

		return nullptr;
	}

	std::string ConvertToBase64(Integer InputIntger)
	{
		std::stringstream Cache;
		Cache << std::hex << InputIntger;
		std::string Source = Cache.str();
		std::cout << Source << std::endl;
		std::string EncodedStr = base64_encode(reinterpret_cast<const unsigned char *>(Source.c_str()),Source.length());

		return EncodedStr;
	}

	void SerilizeCSPublicKey(std::string CSharpEnFilePath, RSA::PublicKey PublicKey)
	{
		freopen(CSharpEnFilePath.c_str(), "w", stdout);

		std::stringstream PublicKeyString;

		PublicKeyString << "<RSAKeyValue>";
		PublicKeyString << "<Modulus>";
		PublicKeyString << ConvertToBase64(PublicKey.GetModulus());
		PublicKeyString << "</Modulus>";
		PublicKeyString << "<Exponent>";
		PublicKeyString << ConvertToBase64(PublicKey.GetPublicExponent());
		PublicKeyString << "</Exponent>";
		PublicKeyString << "</RSAKeyValue>";

		std::cout << PublicKeyString.str() << std::endl;
	}

	void SerilizeCSPrivateKey(std::string CSharpDeFilePath, RSA::PrivateKey PrivateKey)
	{
		freopen(CSharpDeFilePath.c_str(), "w", stdout);

		std::stringstream PrivateKeyString;
		PrivateKeyString << "<RSAKeyValue>";
		PrivateKeyString << "<Modulus>";
		PrivateKeyString << ConvertToBase64(PrivateKey.GetModulus());
		PrivateKeyString << "</Modulus>";
		PrivateKeyString << "<Exponent>";
		PrivateKeyString << ConvertToBase64(PrivateKey.GetPublicExponent());
		PrivateKeyString << "</Exponent>";
		PrivateKeyString << "<P>";
		PrivateKeyString << ConvertToBase64( PrivateKey.GetPrime1());
		PrivateKeyString << "</P>";
		PrivateKeyString << "<Q>";
		PrivateKeyString << ConvertToBase64( PrivateKey.GetPrime2());
		PrivateKeyString << "</Q>";
		PrivateKeyString << "<DP>";
		PrivateKeyString << ConvertToBase64( PrivateKey.GetModPrime1PrivateExponent() );
		PrivateKeyString << "</DP>";
		PrivateKeyString << "<DQ>";
		PrivateKeyString << ConvertToBase64( PrivateKey.GetModPrime2PrivateExponent() );
		PrivateKeyString << "</DQ>";
		PrivateKeyString << "<InverseQ>";
		PrivateKeyString << ConvertToBase64 ( PrivateKey.GetMultiplicativeInverseOfPrime2ModPrime1());
		PrivateKeyString << "</InverseQ>";
		PrivateKeyString << "<D>";
		PrivateKeyString << ConvertToBase64 ( PrivateKey.GetPrivateExponent() );
		PrivateKeyString << "</D>";
		PrivateKeyString << "</RSAKeyValue>";

		std::cout << PrivateKeyString.str() << std::endl;
	}

	void Save(const std::string& filename, const BufferedTransformation& bt)
	{
		FileSink file(filename.c_str());

		bt.CopyTo(file);
		file.MessageEnd();
	}

	void SavePrivateKey(const std::string& filename, const PublicKey& key)
	{
		ByteQueue queue;
		key.Save(queue);
		Save(filename, queue);
	}

	void SavePublicKey(const std::string& filename, const PublicKey& key)
	{
		ByteQueue queue;
		key.Save(queue);
		Save(filename, queue);
	}

	void GenerateOAEPRSAKey(int Size, std::string DeFilePath , std::string EnFilePath,std::string CSharpDeFilePath,std::string CSharpEnFilePath)
	{
		std::string Seed = "Seed";// hard code for test
		RandomPool SeedRandomPool;
		SeedRandomPool.Put((byte *)Seed.c_str(), Seed.length());
		InvertibleRSAFunction Params;
		Params.GenerateRandomWithKeySize(SeedRandomPool, Size);
		
		RSA::PrivateKey PrivateKey(Params);
		RSA::PublicKey PublicKey(Params);
		/*RSAES_PKCS1v15_Decryptor PKCSPrivateKey(PrivateKey);
		RSAES_PKCS1v15_Encryptor PKCSPublicKey(PublicKey);*/

		//
		SavePrivateKey("E:/tmp/decrypt_of.key",PrivateKey);
		SavePrivateKey("E:/tmp/encrypt_of.key", PublicKey);
		//output normal
		Base64Encoder DecFile(new FileSink(DeFilePath.c_str()));
		//PrivateKey.DEREncode(DecFile);
		PrivateKey.Save(DecFile);
		DecFile.MessageEnd();

		Base64Encoder EncFile((new FileSink(EnFilePath.c_str())));
		//PublicKey.DEREncode(EncFile);
		PublicKey.Save(EncFile);
		EncFile.MessageEnd();

		RSAES_OAEP_SHA_Encryptor en(PublicKey);
		std::cout << en.FixedMaxPlaintextLength() <<std::endl;
		//output cs
		/*SerilizeCSPrivateKey(CSharpDeFilePath ,PrivateKey);

		SerilizeCSPublicKey(CSharpEnFilePath , PublicKey);*/
		return;
	}
	
}

int main() {
	GenerateKey::GenerateOAEPRSAKey(4096 , "E:/tmp/decrypt.key" , "E:/tmp/encrypt.key", "E:/tmp/CSdecrypt.key", "E:/tmp/CSencrypt.key");
	return 0;
}