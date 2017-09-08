#include <osrng.h>
#include <rsa.h>
#include <Filter.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>

//using namespace std;
using namespace CryptoPP;

int main() 
{
	std::string message = "http://my.oschina.net/xlplbo/blog";
	printf("message = %s, length = %d\n", message.c_str(), strlen(message.c_str()));

	/*
	//自动生成随机数据
	byte seed[600] = "";
	AutoSeededRandomPool rnd;
	rnd.GenerateBlock(seed, sizeof(seed));
	printf("seed = %s\n", (char *)seed, strlen((char *)seed));

	//生成加密的高质量伪随机字节播种池一体化后的熵
	RandomPool randPool;
	randPool.Put(seed, sizeof(seed));
	*/

	AutoSeededRandomPool  rnd;
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rnd, 4096);

	//printf("%s  --- %s\n",params.GetPrime1(),params.GetPrime2());
	std::cout << params.GetPrime1() << std::endl;
	RSA::PrivateKey privateKey(params);
	RSA::PublicKey publicKey(params);

	//使用OAEP模式
	//RSAES_OAEP_SHA_Decryptor pri(randPool, sizeof(seed));
	//RSAES_OAEP_SHA_Encryptor pub(pri);
	RSAES_OAEP_SHA_Decryptor pri(privateKey);
	RSAES_OAEP_SHA_Encryptor pub(publicKey);
	printf("max plaintext Length = %d,%d\n", pri.FixedMaxPlaintextLength(), pub.FixedMaxPlaintextLength());
	if (pub.FixedMaxPlaintextLength() > message.length())
	{//待加密文本不能大于最大加密长度
		std::string chilper;
		StringSource(message, true, new PK_EncryptorFilter(rnd, pub, new StringSink(chilper)));
		printf("chilper = %s, length = %d\n", chilper.c_str(), strlen(chilper.c_str()));

		std::string txt;
		StringSource(chilper, true, new PK_DecryptorFilter(rnd, pri, new StringSink(txt)));
		printf("txt = %s, length = %d\n", txt.c_str(), strlen(txt.c_str()));
	}

	//使用PKCS1v15模式
	//RSAES_PKCS1v15_Decryptor pri1(randPool, sizeof(seed));
	//RSAES_PKCS1v15_Encryptor pub1(pri1);
	RSAES_PKCS1v15_Decryptor pri1(privateKey);
	RSAES_PKCS1v15_Encryptor pub1(publicKey);
	printf("max plaintext Length = %d,%d\n", pri1.FixedMaxPlaintextLength(), pub1.FixedMaxPlaintextLength());
	if (pub1.FixedMaxPlaintextLength() > message.length())
	{//待加密文本不能大于最大加密长度
		std::string chilper;
		StringSource(message, true, new PK_EncryptorFilter(rnd, pub1, new StringSink(chilper)));
		printf("chilper = %s, length = %d\n", chilper.c_str(), strlen(chilper.c_str()));

		std::string txt;
		StringSource(chilper, true, new PK_DecryptorFilter(rnd, pri1, new StringSink(txt)));
		printf("txt = %s, length = %d\n", txt.c_str(), strlen(txt.c_str()));
	}
}