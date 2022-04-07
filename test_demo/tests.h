#pragma once

#include <string>
#include "Utils/crypto_util.h"

//****************************/
//-- class tests
//****************************/
class tests
{
public:
	// ≤‚ ‘memcpy∂‘unsigned long longøΩ±¥
	static void test_memcpy_ull();
	// ≤‚ ‘hex
	static void test_hex();
	// ≤‚ ‘md5
	static void test_md5();
	// ≤‚ ‘base64
	static void test_base64();
	// ≤‚ ‘aes_256_ecb
	static void test_aes_256_ecb();
	// ≤‚ ‘rsa
	static void test_rsa();
};
