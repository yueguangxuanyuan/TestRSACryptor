#pragma once

#include <string>

namespace EnCryptUtil
{
	std::string EncryptString(std::string InputStr);
	
	std::string DecryptString(std::string InputStr);

	std::string EncryptLongString(std::string InputStr);

	std::string DecryptLongString(std::string InputStr);
}