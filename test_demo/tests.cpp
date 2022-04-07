#include "tests.h"

#ifndef SAFE_FREE
#define SAFE_FREE(p) do { if(p) { free(p); (p) = NULL; } } while(0)
#endif

//****************************/
//-- class tests
//****************************/
//////////////////////////////////////////////////////////////////////////

void tests::test_memcpy_ull()
{
	printf("\n------ Entered: %s\n", __FUNCTION__);

	const size_t nBuf = 8; // sizeof(unsigned long long);
	char pBuf[8] = { 0 };

	unsigned long long ullNum1 = 1234567890;
	memset(pBuf, 0, nBuf);
	memcpy(pBuf, &ullNum1, nBuf);
	printf("ullNum1 = %llu\n", ullNum1);

	unsigned long long ullNum2 = 0;
	memcpy(&ullNum2, pBuf, nBuf);
	printf("ullNum2 = %llu\n", ullNum2);
}

void tests::test_hex()
{
	printf("\n------ Entered: %s\n", __FUNCTION__);

	static const std::string strOri = "HP";
	std::string strHex;
	std::string strBuf;

	// 内存数据转换为十六进制字符串
	do  {
		unsigned char* output_hex = NULL;
		size_t output_hex_len = 0;
		if (crypto_util::buf_to_hexstr((unsigned char*)strOri.c_str(), strOri.size(), &output_hex, &output_hex_len, true) &&
			output_hex != NULL && output_hex_len != 0) {
			strHex.assign((char*)output_hex, output_hex_len);
		}
		SAFE_FREE(output_hex);
	} while (0);

	// 十六进制字符串转换为数据
	do  {
		unsigned char* output_buf = NULL;
		size_t output_buf_len = 0;
		if (crypto_util::hexstr_to_buf((unsigned char*)strHex.c_str(), strHex.size(), &output_buf, &output_buf_len) &&
			output_buf != NULL && output_buf_len != 0) {
			strBuf.assign((char*)output_buf, output_buf_len);
		}
		SAFE_FREE(output_buf);
	} while (0);

	printf("strOri = %s\n", strOri.c_str());
	printf("strHex = %s\n", strHex.c_str());
	printf("strBuf = %s\n", strBuf.c_str());
}

void tests::test_md5()
{
	printf("\n------ Entered: %s\n", __FUNCTION__);

	static const std::string strOri = "HP";
	std::string strMd5;

	crypto_util::md5_str_hex(strOri, strMd5, true);

	printf("strOri = %s\n", strOri.c_str());
	printf("strMd5 = %s\n", strMd5.c_str());
}

void tests::test_base64()
{
	printf("\n------ Entered: %s\n", __FUNCTION__);

	static const std::string strOri = "HP - hello base64";
	std::string strEnc;
	std::string strDec;

	crypto_util::base64_encode_str(strOri, strEnc, false);
	crypto_util::base64_decode_str(strEnc, strDec, false);

	printf("strOri = %s\n", strOri.c_str());
	printf("strEnc = %s\n", strEnc.c_str());
	printf("strDec = %s\n", strDec.c_str());
}

void tests::test_aes_256_ecb()
{
	printf("\n------ Entered: %s\n", __FUNCTION__);

	static const char* AES_KEY = "12345678901234567890123456789012"; // 32个字节
	const size_t nBuf = 16;
	unsigned char pBuf[16] = { 0 };
	memset(pBuf, 0, nBuf);

	// 加密
	do  {
		unsigned long long ullNum1 = 12345678901234567890; // 取值范围[0 ~ 18446744073709551615]
		unsigned char* output_enc = NULL;
		size_t output_enc_len = 0;
		if (crypto_util::aes_256_ecb_encode((unsigned char*)AES_KEY, (unsigned char*)&ullNum1, sizeof(ullNum1), &output_enc, &output_enc_len, true) &&
			output_enc != NULL && output_enc_len == nBuf) {
			memcpy(pBuf, output_enc, nBuf);
		}
		SAFE_FREE(output_enc);
		printf("ullNum1 = %llu\n", ullNum1);
	} while (0);

	// 解密
	do  {
		unsigned long long ullNum2 = 0;
		unsigned char* output_dec = NULL;
		size_t output_dec_len = 0;
		if (crypto_util::aes_256_ecb_decode((unsigned char*)AES_KEY, pBuf, nBuf, &output_dec, &output_dec_len, true) &&
			output_dec != NULL && output_dec_len == sizeof(ullNum2)) {
			memcpy(&ullNum2, output_dec, output_dec_len);
		}
		SAFE_FREE(output_dec);
		printf("ullNum2 = %llu\n", ullNum2);
	} while (0);
}

void tests::test_rsa()
{
	printf("\n------ Entered: %s\n", __FUNCTION__);

	std::string public_key;
	std::string private_key;

	crypto_util::generate_rsa_key(public_key, private_key);

	printf("public_key = \n%s\n", public_key.c_str());
	printf("private_key = \n%s\n", private_key.c_str());
}
