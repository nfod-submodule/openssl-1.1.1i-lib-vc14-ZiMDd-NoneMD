#include "crypto_util.h"
#include <vector>
#include <assert.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include "openssl/aes.h"
#include "openssl/rsa.h"
#include "openssl/md5.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/buffer.h"

#ifndef SAFE_ASSERT
#ifdef _DEBUG
#define SAFE_ASSERT(cond) assert(cond)
#else
#define SAFE_ASSERT(cond)
#endif
#endif

#ifndef SAFE_DELETE_ARRAY
#define SAFE_DELETE_ARRAY(p) do { if(p) { delete[] (p); (p) = NULL; } } while(0)
#endif

#ifndef SAFE_FREE
#define SAFE_FREE(p) do { if(p) { free(p); (p) = NULL; } } while(0)
#endif

//****************************/
//-- class crypto_util
//****************************/
//////////////////////////////////////////////////////////////////////////

/*************************************************************************
** hex
*************************************************************************/

int crypto_util::hexchar_to_int(unsigned char ch)
{
	switch (ch) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': case 'A': return 0x0A;
	case 'b': case 'B': return 0x0B;
	case 'c': case 'C': return 0x0C;
	case 'd': case 'D': return 0x0D;
	case 'e': case 'E': return 0x0E;
	case 'f': case 'F': return 0x0F;
	}
	return -1;
}

bool crypto_util::hexstr_to_buf(
	const unsigned char* input,
	const size_t input_len,
	unsigned char** output,
	size_t* output_len)
{
	if (!input || input_len == 0 || !output || !output_len) {
		return false;
	}

	size_t buffer_len = input_len >> 1;
	unsigned char* buffer = (unsigned char*)malloc(buffer_len + 1);
	if (buffer == NULL) {
		return false;
	}
	memset(buffer, 0, buffer_len + 1);

	unsigned char ch, cl;
	int chi, cli;
	const unsigned char* p;
	unsigned char* q;

	for (p = input, q = buffer; *p; )
	{
		ch = *p++;
		cl = *p++;
		if (!cl) {
			SAFE_FREE(buffer);
			return false;
		}
		cli = hexchar_to_int(cl);
		chi = hexchar_to_int(ch);
		if (cli < 0 || chi < 0) {
			SAFE_FREE(buffer);
			return false;
		}
		*q++ = (unsigned char)((chi << 4) | cli);
	}

	SAFE_ASSERT(q - buffer == buffer_len);
	*output = buffer;
	*output_len = buffer_len;
	return true;
}

bool crypto_util::buf_to_hexstr(
	const unsigned char* input,
	const size_t input_len,
	unsigned char** output,
	size_t* output_len,
	bool toUppercase)
{
	if (!input || input_len == 0 || !output || !output_len) {
		return false;
	}

	static const size_t HEXLEN = 2;
	size_t buffer_len = input_len * HEXLEN;
	unsigned char* buffer = (unsigned char*)malloc(buffer_len + 1);
	if (buffer == NULL) {
		return false;
	}
	memset(buffer, 0, buffer_len + 1);

	static const unsigned char hexdig_upper[] = "0123456789ABCDEF";
	static const unsigned char hexdig_lower[] = "0123456789abcdef";
	const unsigned char* hexdig = toUppercase ? hexdig_upper : hexdig_lower;

	size_t i;
	const unsigned char* p;
	unsigned char* q;

	for (i = 0, p = input, q = buffer; i < input_len; ++i, ++p) {
		*q++ = hexdig[(*p >> 4) & 0xf];
		*q++ = hexdig[*p & 0xf];
	}

	*output = buffer;
	*output_len = buffer_len;
	return true;
}

bool crypto_util::buf_t2_hexstr(
	const unsigned char* input,
	const size_t input_len,
	unsigned char** output,
	size_t* output_len,
	bool toUppercase)
{
	if (!input || input_len == 0 || !output || !output_len) {
		return false;
	}

	static const size_t HEXLEN = 2;
	size_t buffer_len = input_len * HEXLEN;
	unsigned char* buffer = (unsigned char*)malloc(buffer_len + 1);
	if (buffer == NULL) {
		return false;
	}
	memset(buffer, 0, buffer_len + 1);

	const char* fmt = toUppercase ? "%02X" : "%02x";
	char ch[HEXLEN + 1] = { 0 };
	for (size_t i = 0; i < input_len; ++i) {
		memset(ch, 0, HEXLEN + 1);
		::_snprintf_s(ch, sizeof(ch), fmt, input[i]);
		memcpy(buffer + HEXLEN * i, ch, HEXLEN);
	}

	*output = buffer;
	*output_len = buffer_len;
	return true;
}

/*************************************************************************
** md5
*************************************************************************/

bool crypto_util::md5_buf_hex(
	const unsigned char* input,
	const size_t input_len,
	unsigned char** output,
	size_t* output_len,
	bool toUppercase)
{
	if (!input || input_len == 0 || !output || !output_len) {
		return false;
	}

	static const size_t MD5LEN = 16;
	unsigned char md5_result[MD5LEN + 1] = { 0 };
	MD5(input, input_len, md5_result);

	return buf_to_hexstr(md5_result, MD5LEN, output, output_len, toUppercase);
}

bool crypto_util::md5_str_hex(
	const std::string& input,
	std::string& output,
	bool toUppercase)
{
	output.clear();
	unsigned char* output_hex = NULL;
	size_t output_hex_len = 0;
	bool bRet = md5_buf_hex((const unsigned char*)input.c_str(), input.size(), &output_hex, &output_hex_len, toUppercase);
	if (bRet && output_hex != NULL && output_hex_len != 0) {
		output.assign((char*)output_hex, output_hex_len);
		SAFE_ASSERT(output.size() == output_hex_len);
	}
	SAFE_FREE(output_hex);
	return bRet;
}

bool crypto_util::md5_file_hex(
	const std::string& filepath,
	std::string& output,
	bool toUppercase)
{
	if (filepath.empty()) {
		return false;
	}
	std::ifstream ifile(filepath.c_str(), std::ios::in | std::ios::binary);
	if (ifile.fail()) {
		return false;
	}

	static const size_t MAXLEN = 1024;
	char DataBuffer[MAXLEN] = { 0 };
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	while (!ifile.eof())
	{
		ifile.read(DataBuffer, MAXLEN);
		size_t count_len = static_cast<size_t>(ifile.gcount());
		if (count_len > 0) {
			// 将当前文件块加入并更新MD5
			MD5_Update(&md5_ctx, DataBuffer, count_len);
		}
	}
	static const size_t MD5LEN = 16;
	unsigned char md5_result[MD5LEN + 1] = { 0 };
	MD5_Final(md5_result, &md5_ctx);

	output.clear();
	for (size_t i = 0; i < MD5LEN; ++i) {
		std::ostringstream oss;
		if (toUppercase) { oss << std::uppercase; }
		oss << std::hex << static_cast<int>(md5_result[i]);
		output.append(oss.str());
	}
	return true;
}

/*************************************************************************
** base64
*************************************************************************/

bool crypto_util::base64_encode(
	const unsigned char* input,
	const size_t input_len,
	unsigned char** output,
	size_t* output_len,
	bool with_new_line)
{
	if (!input || input_len == 0 || !output || !output_len) {
		return false;
	}

	BIO* b64 = BIO_new(BIO_f_base64());
	if (!with_new_line) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	BIO* bmem = BIO_new(BIO_s_mem());
	bmem = BIO_push(b64, bmem);
	BIO_write(bmem, input, static_cast<int>(input_len));
	BIO_flush(bmem);
	BUF_MEM* bptr = NULL;
	BIO_get_mem_ptr(bmem, &bptr);

	size_t length = bptr->length;
	unsigned char* buffer = (unsigned char*)malloc(length + 1);
	memset(buffer, 0, length + 1);
	memcpy(buffer, bptr->data, length);
	buffer[length] = 0;
	BIO_free_all(bmem);

	*output = buffer;
	*output_len = length;
	return true;
}

bool crypto_util::base64_decode(
	const unsigned char* input,
	const size_t input_len,
	unsigned char** output,
	size_t* output_len,
	bool with_new_line)
{
	if (!input || input_len == 0 || !output || !output_len) {
		return false;
	}

	BIO* b64 = BIO_new(BIO_f_base64());
	if (!with_new_line) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	BIO* bmem = BIO_new_mem_buf(input, static_cast<int>(input_len));
	bmem = BIO_push(b64, bmem);

	unsigned char* buffer = (unsigned char*)malloc(input_len);
	memset(buffer, 0, input_len);
	int length = BIO_read(bmem, buffer, static_cast<int>(input_len));
	BIO_free_all(bmem);

	*output = buffer;
	*output_len = length;
	return true;
}

bool crypto_util::base64_encode_str(
	const std::string& input,
	std::string& output,
	bool with_new_line)
{
	output.clear();
	unsigned char* output_enc = NULL;
	size_t output_enc_len = 0;
	bool bRet = base64_encode((const unsigned char*)input.c_str(), input.size(), &output_enc, &output_enc_len, with_new_line);
	if (bRet && output_enc != NULL && output_enc_len != 0) {
		output.assign((char*)output_enc, output_enc_len);
		SAFE_ASSERT(output.size() == output_enc_len);
	}
	SAFE_FREE(output_enc);
	return bRet;
}

bool crypto_util::base64_decode_str(
	const std::string& input,
	std::string& output,
	bool with_new_line)
{
	output.clear();
	unsigned char* output_dec = NULL;
	size_t output_dec_len = 0;
	bool bRet = base64_decode((const unsigned char*)input.c_str(), input.size(), &output_dec, &output_dec_len, with_new_line);
	if (bRet && output_dec != NULL && output_dec_len != 0) {
		output.assign((char*)output_dec, output_dec_len);
		SAFE_ASSERT(output.size() == output_dec_len);
	}
	SAFE_FREE(output_dec);
	return bRet;
}

/*************************************************************************
** aes - 高级加密标准（Advanced Encryption Standard，AES）
*************************************************************************/

bool crypto_util::aes_256_ecb_encode_format(
	const std::string& key,
	const std::string& input,
	std::string& output,
	bool padding,
	bool format_hex,
	bool toUppercase /*= false*/)
{
	output.clear();
	unsigned char* output_enc = NULL;
	size_t output_enc_len = 0;
	bool bRet = aes_256_ecb_encode((const unsigned char*)key.c_str(), (const unsigned char*)input.c_str(), input.size(), &output_enc, &output_enc_len, padding);
	if (bRet && output_enc != NULL && output_enc_len != 0)
	{
		if (format_hex)
		{// hex
			unsigned char* output_enc_hex = NULL;
			size_t output_enc_hex_len = 0;
			bRet = buf_to_hexstr(output_enc, output_enc_len, &output_enc_hex, &output_enc_hex_len, toUppercase);
			if (bRet && output_enc_hex != NULL && output_enc_hex_len != 0) {
				output.assign((char*)output_enc_hex, output_enc_hex_len);
				SAFE_ASSERT(output.size() == output_enc_hex_len);
			}
			SAFE_FREE(output_enc_hex);
		}
		else
		{// base64
			unsigned char* output_enc_base64 = NULL;
			size_t output_enc_base64_len = 0;
			bRet = base64_encode(output_enc, output_enc_len, &output_enc_base64, &output_enc_base64_len, false);
			if (bRet && output_enc_base64 != NULL && output_enc_base64_len != 0) {
				output.assign((char*)output_enc_base64, output_enc_base64_len);
				SAFE_ASSERT(output.size() == output_enc_base64_len);
			}
			SAFE_FREE(output_enc_base64);
		}
	}
	SAFE_FREE(output_enc);
	return bRet;
}

bool crypto_util::aes_256_ecb_decode_format(
	const std::string& key,
	const std::string& input,
	std::string& output,
	bool padding,
	bool format_hex)
{
	output.clear();
	bool bRet = false;
	if (format_hex)
	{// hex
		unsigned char* input_buf = NULL;
		size_t input_buf_len = 0;
		bRet = hexstr_to_buf((const unsigned char*)input.c_str(), input.size(), &input_buf, &input_buf_len);
		if (bRet && input_buf != NULL && input_buf_len != 0) {
			unsigned char* output_dec = NULL;
			size_t output_dec_len = 0;
			bRet = aes_256_ecb_decode((const unsigned char*)key.c_str(), input_buf, input_buf_len, &output_dec, &output_dec_len, padding);
			if (bRet && output_dec != NULL && output_dec_len != 0) {
				output.assign((char*)output_dec, output_dec_len);
				SAFE_ASSERT(output.size() == output_dec_len);
			}
			SAFE_FREE(output_dec);
		}
		SAFE_FREE(input_buf);
	}
	else
	{// base64
		unsigned char* input_buf = NULL;
		size_t input_buf_len = 0;
		bRet = base64_decode((const unsigned char*)input.c_str(), input.size(), &input_buf, &input_buf_len, false);
		if (bRet && input_buf != NULL && input_buf_len != 0) {
			unsigned char* output_dec = NULL;
			size_t output_dec_len = 0;
			bRet = aes_256_ecb_decode((const unsigned char*)key.c_str(), input_buf, input_buf_len, &output_dec, &output_dec_len, padding);
			if (bRet && output_dec != NULL && output_dec_len != 0) {
				output.assign((char*)output_dec, output_dec_len);
				SAFE_ASSERT(output.size() == output_dec_len);
			}
			SAFE_FREE(output_dec);
		}
		SAFE_FREE(input_buf);
	}
	return bRet;
}

bool crypto_util::aes_256_ecb_encode(
	const unsigned char* key,
	const unsigned char* input,
	const size_t input_len,
	unsigned char** output,
	size_t* output_len,
	bool padding)
{
	static const int rv_ok = 1;
	unsigned char* buff = NULL;
	EVP_CIPHER_CTX* ctx = NULL;

	bool bRet = false;
	do
	{
		// 检查参数有效性
		if (!key || !input || input_len == 0 || !output || !output_len) {
			break;
		}
		// 计算加密缓冲长度，申请内存并拷贝清零
		size_t buff_len = ((input_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
		buff = (unsigned char*)malloc(buff_len + 1);
		if (buff == NULL) {
			break;
		}
		memset(buff, 0, buff_len + 1);
		// 初始设置
		ctx = EVP_CIPHER_CTX_new();
		if (rv_ok != EVP_CIPHER_CTX_init(ctx) ||
			rv_ok != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) {
			break;
		}
		EVP_CIPHER_CTX_set_padding(ctx, padding ? 1 : 0); // 1:表示填充，0:表示不填充
		// 加密数据
		unsigned char* enc_ptr = buff;
		int enc_len = 0;
		if (rv_ok != EVP_EncryptUpdate(ctx, enc_ptr, &enc_len, input, static_cast<int>(input_len))) {
			break;
		}
		enc_ptr += enc_len;
		if (rv_ok != EVP_EncryptFinal_ex(ctx, enc_ptr, &enc_len)) {
			break;
		}
		enc_ptr += enc_len;
		// 数据拷贝
		size_t out_len = enc_ptr - buff;
		unsigned char* out = (unsigned char*)malloc(out_len + 1);
		if (out == NULL) {
			break;
		}
		memset(out, 0, out_len + 1);
		memcpy(out, buff, out_len);
		// 结果赋值
		*output = out;
		*output_len = out_len;
		// 成功
		bRet = true;
	} while (0);

	SAFE_FREE(buff);
	if (ctx) {
		EVP_CIPHER_CTX_cleanup(ctx);
		EVP_CIPHER_CTX_free(ctx);
	}
	return bRet;
}

bool crypto_util::aes_256_ecb_decode(
	const unsigned char* key,
	const unsigned char* input,
	const size_t input_len,
	unsigned char** output,
	size_t* output_len,
	bool padding)
{
	static const int rv_ok = 1;
	unsigned char* buff = NULL;
	EVP_CIPHER_CTX* ctx = NULL;

	bool bRet = false;
	do
	{
		// 检查参数有效性
		if (!key || !input || input_len == 0 || !output || !output_len) {
			break;
		}
		// 计算解密缓冲长度，申请内存并拷贝清零
		size_t buff_len = ((input_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
		buff = (unsigned char*)malloc(buff_len + 1);
		if (buff == NULL) {
			break;
		}
		memset(buff, 0, buff_len + 1);
		// 初始设置
		ctx = EVP_CIPHER_CTX_new();
		if (rv_ok != EVP_CIPHER_CTX_init(ctx) ||
			rv_ok != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) {
			break;
		}
		EVP_CIPHER_CTX_set_padding(ctx, padding ? 1 : 0); // 1:表示填充，0:表示不填充
		// 解密数据
		unsigned char* dec_ptr = buff;
		int dec_len = 0;
		if (rv_ok != EVP_DecryptUpdate(ctx, dec_ptr, &dec_len, input, static_cast<int>(input_len))) {
			break;
		}
		dec_ptr += dec_len;
		if (rv_ok != EVP_DecryptFinal_ex(ctx, dec_ptr, &dec_len)) {
			break;
		}
		dec_ptr += dec_len;
		// 数据拷贝
		size_t out_len = dec_ptr - buff;
		unsigned char* out = (unsigned char*)malloc(out_len + 1);
		if (out == NULL) {
			break;
		}
		memset(out, 0, out_len + 1);
		memcpy(out, buff, out_len);
		// 结果赋值
		*output = out;
		*output_len = out_len;
		// 成功
		bRet = true;
	} while (0);

	SAFE_FREE(buff);
	if (ctx) {
		EVP_CIPHER_CTX_cleanup(ctx);
		EVP_CIPHER_CTX_free(ctx);
	}
	return bRet;
}

bool crypto_util::aes_256_ecb_encode_nopadding(
	const unsigned char* key,
	const unsigned char* input,
	const size_t input_len,
	unsigned char* output_ptr)
{
	// 检查参数有效性
	if (!key || !input || input_len == 0 || !output_ptr) {
		return false;
	}
	// 必须满足加密前数据长度是AES_BLOCK_SIZE的整数倍
	if (0 != input_len % AES_BLOCK_SIZE) {
		return false;
	}
	// 设置密钥
	AES_KEY aes_key;
	if (0 != AES_set_encrypt_key(key, 256, &aes_key)) {
		return false;
	}
	// 拷贝内存
	unsigned char* buff = output_ptr;
	memcpy(buff, input, input_len);
	// 数据加密
	for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE) {
		AES_encrypt(buff + i, buff + i, &aes_key);
	}
	return true;
}

bool crypto_util::aes_256_ecb_decode_nopadding(
	const unsigned char* key,
	const unsigned char* input,
	const size_t input_len,
	unsigned char* output_ptr)
{
	// 检查参数有效性
	if (!key || !input || input_len == 0 || !output_ptr) {
		return false;
	}
	// 必须满足解密前数据长度是AES_BLOCK_SIZE的整数倍
	if (0 != input_len % AES_BLOCK_SIZE) {
		return false;
	}
	// 设置密钥
	AES_KEY aes_key;
	if (0 != AES_set_decrypt_key(key, 256, &aes_key)) {
		return false;
	}
	// 拷贝内存
	unsigned char* buff = output_ptr;
	memcpy(buff, input, input_len);
	// 数据解密
	for (size_t i = 0; i < input_len; i += AES_BLOCK_SIZE) {
		AES_decrypt(buff + i, buff + i, &aes_key);
	}
	return true;
}

bool crypto_util::aes_256_ofb_encode_nopadding(
	const unsigned char* key,
	const unsigned char* input,
	const size_t input_len,
	unsigned char* output_ptr)
{
	// 检查参数有效性
	if (!key || !input || input_len == 0 || !output_ptr) {
		return false;
	}
	// 设置密钥
	AES_KEY aes_key;
	if (0 != AES_set_encrypt_key(key, 256, &aes_key)) {
		return false;
	}
	// 初始向量（长度必须是16字节，选取密钥key前16字节）
	unsigned char ivec[16] = { 0 };
	memcpy(ivec, key, 16);
	// 清理内存
	unsigned char* buff = output_ptr;
	memset(buff, 0, input_len);
	// 数据加密
	int num = 0;
	AES_ofb128_encrypt(input, buff, input_len, &aes_key, ivec, &num);
	return true;
}

bool crypto_util::aes_256_ofb_decode_nopadding(
	const unsigned char* key,
	const unsigned char* input,
	const size_t input_len,
	unsigned char* output_ptr)
{
	// 特别注意：解密与加密执行相同的操作
	return aes_256_ofb_encode_nopadding(key, input, input_len, output_ptr);
}

/*************************************************************************
** rsa - 非对称加密算法
*************************************************************************/

bool crypto_util::generate_rsa_key(
	std::string& public_key,
	std::string& private_key,
	int key_bits)
{
	bool bRet = false;

	RSA* rsa_pt = NULL;
	BIGNUM* bne = NULL;
	BIO* bp_pub = NULL;
	BIO* bp_pri = NULL;
	EVP_PKEY* ev_pkey = NULL;

	do
	{
		static const unsigned long e = RSA_F4;
		static const int ret_ok = 1;

		bne = BN_new();
		if (ret_ok != BN_set_word(bne, e)) {
			printf("BN_set_word failed.");
			break;
		}
		rsa_pt = RSA_new();
		if (ret_ok != RSA_generate_key_ex(rsa_pt, key_bits, bne, NULL)) {
			printf("RSA_generate_key_ex failed.");
			break;
		}
		ev_pkey = EVP_PKEY_new();
		if (ret_ok != EVP_PKEY_set1_RSA(ev_pkey, rsa_pt)) {
			printf("EVP_PKEY_set1_RSA failed.");
			break;
		}
		bp_pub = BIO_new(BIO_s_mem());
		if (ret_ok != PEM_write_bio_PUBKEY(bp_pub, ev_pkey)) {
			printf("PEM_write_bio_PUBKEY failed.");
			break;
		}
		bp_pri = BIO_new(BIO_s_mem());
		if (ret_ok != PEM_write_bio_PKCS8PrivateKey(bp_pri, ev_pkey, NULL, NULL, 0, NULL, NULL)) {
			printf("PEM_write_bio_RSAPrivateKey failed.");
			break;
		}

		int    bp_pub_len = BIO_pending(bp_pub);
		char*  bp_pub_key = (char *)malloc(bp_pub_len + 1);
		memset(bp_pub_key, 0, bp_pub_len + 1);
		BIO_read(bp_pub, bp_pub_key, bp_pub_len);
		public_key = bp_pub_key;
		SAFE_FREE(bp_pub_key);

		int    bp_pri_len = BIO_pending(bp_pri);
		char*  bp_pri_key = (char *)malloc(bp_pri_len + 1);
		memset(bp_pri_key, 0, bp_pri_len + 1);
		BIO_read(bp_pri, bp_pri_key, bp_pri_len);
		private_key = bp_pri_key;
		SAFE_FREE(bp_pri_key);

		bRet = true;
	} while (0);

	BIO_free_all(bp_pub);
	BIO_free_all(bp_pri);
	RSA_free(rsa_pt);
	BN_free(bne);

	return bRet;
}

std::string crypto_util::serialize_rsa_key(
	const std::string& key_structured)
{
	std::vector<std::string> vec_strs;
	std::string str(key_structured);
	std::string sub;
	std::string delim("\n");
	size_t start = 0;
	size_t found = std::string::npos;
	do
	{
		found = str.find(delim, start);
		if (found == std::string::npos) {
			if (start < str.length()) {
				vec_strs.push_back(str.substr(start));
			}
			break;
		}
		sub = str.substr(start, found - start);
		if (!sub.empty()) {
			vec_strs.push_back(sub);
		}
		start = found + delim.length();
	} while (1);

	std::string ret;
	size_t nSz = vec_strs.size();
	if (nSz > 2/*开头与结尾各占1个*/) {
		for (size_t i = 1; i < nSz - 1; ++i) {
			ret += vec_strs.at(i);
		}
	}
	return ret;
}

std::string crypto_util::struct_public_key(
	const std::string& public_key_serialized)
{
	const size_t line_num = 64;
	const std::string line_end = "\n";
	const std::string pub_head = "-----BEGIN PUBLIC KEY-----";
	const std::string pub_tail = "-----END PUBLIC KEY-----";

	std::string ret = pub_head + line_end;
	std::string str(public_key_serialized);
	std::string sub;
	size_t start = 0;
	do
	{
		if (start >= str.size()) {
			break;
		}
		size_t sub_num = str.size() - start;
		if (sub_num > line_num) {
			sub_num = line_num;
		}
		sub = str.substr(start, sub_num);
		ret.append(sub).append(line_end);
		start += sub_num;
	} while (1);
	ret.append(pub_tail);
	return ret;
}

std::string crypto_util::struct_private_key(
	const std::string& private_key_serialized)
{
	const size_t line_num = 64;
	const std::string line_end = "\n";
	const std::string pri_head = "-----BEGIN PRIVATE KEY-----";
	const std::string pri_tail = "-----END PRIVATE KEY-----";

	std::string ret = pri_head + line_end;
	std::string str(private_key_serialized);
	std::string sub;
	size_t start = 0;
	do
	{
		if (start >= str.size()) {
			break;
		}
		size_t sub_num = str.size() - start;
		if (sub_num > line_num) {
			sub_num = line_num;
		}
		sub = str.substr(start, sub_num);
		ret.append(sub).append(line_end);
		start += sub_num;
	} while (1);
	ret.append(pri_tail);
	return ret;
}

bool crypto_util::rsa_public_key_encrypt(
	const std::string& public_key,
	const std::string& input,
	std::string& output)
{
	bool bRet = false;
	RSA* rsa_pt = NULL;
	BIO* bp_pub = NULL;

	do
	{
		bp_pub = BIO_new_mem_buf(public_key.c_str(), (int)public_key.size());
		if (!bp_pub) {
			break;
		}
		rsa_pt = PEM_read_bio_RSA_PUBKEY(bp_pub, &rsa_pt, NULL, NULL);
		if (!rsa_pt) {
			break;
		}
		int output_enc_len = RSA_size(rsa_pt);
		unsigned char* output_enc = new unsigned char[output_enc_len + 1];
		int ret_len = RSA_public_encrypt((int)input.size(), (const unsigned char*)input.c_str(), output_enc, rsa_pt, RSA_PKCS1_PADDING);
		if (ret_len < 0) {
			SAFE_DELETE_ARRAY(output_enc);
			break;
		}
		unsigned char* output_base64 = NULL;
		size_t output_base64_len = 0;
		if (!base64_encode(output_enc, ret_len, &output_base64, &output_base64_len, false) ||
			output_base64 == NULL ||
			output_base64_len == 0) {
			SAFE_DELETE_ARRAY(output_enc);
			SAFE_FREE(output_base64);
			break;
		}
		output.assign((char*)output_base64, output_base64_len);
		SAFE_ASSERT(output.size() == output_base64_len);
		SAFE_DELETE_ARRAY(output_enc);
		SAFE_FREE(output_base64);

		bRet = true;
	} while (0);

	BIO_free_all(bp_pub);
	RSA_free(rsa_pt);

	return bRet;
}

bool crypto_util::rsa_public_key_decrypt(
	const std::string& public_key,
	const std::string& input,
	std::string& output)
{
	bool bRet = false;
	RSA* rsa_pt = NULL;
	BIO* bp_pub = NULL;

	do
	{
		bp_pub = BIO_new_mem_buf(public_key.c_str(), (int)public_key.size());
		if (!bp_pub) {
			break;
		}
		rsa_pt = PEM_read_bio_RSA_PUBKEY(bp_pub, &rsa_pt, NULL, NULL);
		if (!rsa_pt) {
			break;
		}
		unsigned char* input_base64_dec = NULL;
		size_t input_base64_dec_len = 0;
		if (!base64_decode((const unsigned char*)input.c_str(), input.size(), &input_base64_dec, &input_base64_dec_len, false) ||
			input_base64_dec == NULL ||
			input_base64_dec_len == 0) {
			SAFE_FREE(input_base64_dec);
			break;
		}
		int output_dec_len = RSA_size(rsa_pt);
		unsigned char* output_dec = new unsigned char[output_dec_len + 1];
		int ret_len = RSA_public_decrypt((int)input_base64_dec_len, input_base64_dec, output_dec, rsa_pt, RSA_PKCS1_PADDING);
		if (ret_len < 0) {
			SAFE_FREE(input_base64_dec);
			SAFE_DELETE_ARRAY(output_dec);
			break;
		}
		output.assign((char*)output_dec, ret_len);
		SAFE_ASSERT(output.size() == ret_len);
		SAFE_FREE(input_base64_dec);
		SAFE_DELETE_ARRAY(output_dec);

		bRet = true;
	} while (0);

	BIO_free_all(bp_pub);
	RSA_free(rsa_pt);

	return bRet;
}

bool crypto_util::rsa_private_key_encrypt(
	const std::string& private_key,
	const std::string& input,
	std::string& output)
{
	bool bRet = false;
	RSA* rsa_pt = NULL;
	BIO* bp_pri = NULL;

	do
	{
		bp_pri = BIO_new_mem_buf(private_key.c_str(), (int)private_key.size());
		if (!bp_pri) {
			break;
		}
		rsa_pt = PEM_read_bio_RSAPrivateKey(bp_pri, &rsa_pt, NULL, NULL);
		if (!rsa_pt) {
			break;
		}
		int output_enc_len = RSA_size(rsa_pt);
		unsigned char* output_enc = new unsigned char[output_enc_len + 1];
		int ret_len = RSA_private_encrypt((int)input.size(), (const unsigned char*)input.c_str(), output_enc, rsa_pt, RSA_PKCS1_PADDING);
		if (ret_len < 0) {
			SAFE_DELETE_ARRAY(output_enc);
			break;
		}
		unsigned char* output_base64 = NULL;
		size_t output_base64_len = 0;
		if (!base64_encode(output_enc, ret_len, &output_base64, &output_base64_len, false) ||
			output_base64 == NULL ||
			output_base64_len == 0) {
			SAFE_DELETE_ARRAY(output_enc);
			SAFE_FREE(output_base64);
			break;
		}
		output.assign((char*)output_base64, output_base64_len);
		SAFE_ASSERT(output.size() == output_base64_len);
		SAFE_DELETE_ARRAY(output_enc);
		SAFE_FREE(output_base64);

		bRet = true;
	} while (0);

	BIO_free_all(bp_pri);
	RSA_free(rsa_pt);

	return bRet;
}

bool crypto_util::rsa_private_key_decrypt(
	const std::string& private_key,
	const std::string& input,
	std::string& output)
{
	bool bRet = false;
	RSA* rsa_pt = NULL;
	BIO* bp_pri = NULL;

	do
	{
		bp_pri = BIO_new_mem_buf(private_key.c_str(), (int)private_key.size());
		if (!bp_pri) {
			break;
		}
		rsa_pt = PEM_read_bio_RSAPrivateKey(bp_pri, &rsa_pt, NULL, NULL);
		if (!rsa_pt) {
			break;
		}
		unsigned char* input_base64_dec = NULL;
		size_t input_base64_dec_len = 0;
		if (!base64_decode((const unsigned char*)input.c_str(), input.size(), &input_base64_dec, &input_base64_dec_len, false) ||
			input_base64_dec == NULL ||
			input_base64_dec_len == 0) {
			SAFE_FREE(input_base64_dec);
			break;
		}
		int output_dec_len = RSA_size(rsa_pt);
		unsigned char* output_dec = new unsigned char[output_dec_len + 1];
		int ret_len = RSA_private_decrypt((int)input_base64_dec_len, input_base64_dec, output_dec, rsa_pt, RSA_PKCS1_PADDING);
		if (ret_len < 0) {
			SAFE_FREE(input_base64_dec);
			SAFE_DELETE_ARRAY(output_dec);
			break;
		}
		output.assign((char*)output_dec, ret_len);
		SAFE_ASSERT(output.size() == ret_len);
		SAFE_FREE(input_base64_dec);
		SAFE_DELETE_ARRAY(output_dec);

		bRet = true;
	} while (0);

	BIO_free_all(bp_pri);
	RSA_free(rsa_pt);

	return bRet;
}
