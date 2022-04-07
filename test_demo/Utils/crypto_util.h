#pragma once

#include <string>

//****************************/
//-- class crypto_util
//****************************/
class crypto_util
{
public:
	/*************************************************************************
	** hex
	*************************************************************************/
	/**
	 * 十六进制字符转换为数值
	**/
	static int hexchar_to_int(unsigned char ch);

	/**
	 * 十六进制字符串转换为数据
	 * @param input       [in]  输入十六进制字符串数据
	 * @param input_len   [in]  输入十六进制字符串长度
	 * @param output      [out] 输出数据（内存由函数内部malloc创建，需要调用者使用完毕后free释放）
	 * @param output_len  [out] 输出长度
	 * @return true=成功，false=失败
	**/
	static bool hexstr_to_buf(
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len);

	/**
	 * 内存数据转换为十六进制字符串
	 * @param input       [in]  输入内存数据
	 * @param input_len   [in]  输入内存长度
	 * @param output      [out] 输出十六进制字符串数据（内存由函数内部malloc创建，需要调用者使用完毕后free释放）
	 * @param output_len  [out] 输出十六进制字符串长度
	 * @param toUppercase [in]  是否大写（true=大写，false=小写）
	 * @return true=成功，false=失败
	**/
	static bool buf_to_hexstr(
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool toUppercase);

	static bool buf_t2_hexstr(
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool toUppercase);

public:
	/*************************************************************************
	** md5
	*************************************************************************/
	/**
	 * 内存数据md5后转换为十六进制字符串
	 * @param input       [in]  输入内存数据
	 * @param input_len   [in]  输入内存长度
	 * @param output      [out] 输出md5后十六进制字符串数据（内存由函数内部malloc创建，需要调用者使用完毕后free释放）
	 * @param output_len  [out] 输出md5后十六进制字符串长度（32字节）
	 * @param toUppercase [in]  是否大写（true=大写，false=小写）
	 * @return true=成功，false=失败
	**/
	static bool md5_buf_hex(
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool toUppercase);

	/**
	 * 字符串数据md5后转换为十六进制字符串
	 * @param input       [in]  输入字符串数据
	 * @param output      [out] 输出md5后十六进制字符串数据（32字节）
	 * @param toUppercase [in]  是否大写（true=大写，false=小写）
	 * @return true=成功，false=失败
	**/
	static bool md5_str_hex(
		const std::string& input,
		std::string& output,
		bool toUppercase);

	/**
	 * 文件数据md5后转换为十六进制字符串
	 * @param filepath    [in]  文件路径
	 * @param output      [out] 输出md5后十六进制字符串数据（32字节）
	 * @param toUppercase [in]  是否大写（true=大写，false=小写）
	 * @return true=成功，false=失败
	**/
	static bool md5_file_hex(
		const std::string& filepath,
		std::string& output,
		bool toUppercase);

public:
	/*************************************************************************
	** base64
	*************************************************************************/
	/**
	 * base64加密
	 * @param input         [in]  输入加密前数据
	 * @param input_len     [in]  输入加密前长度
	 * @param output        [out] 输出加密后数据（内存由函数内部malloc创建，需要调用者使用完毕后free释放）
	 * @param output_len    [out] 输出加密后长度
	 * @param with_new_line [in]  true=编码(encode)结果每64个字符换行一次，false=编码(encode)结果不换行
	 * @return true=成功，false=失败
	**/
	static bool base64_encode(
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool with_new_line = false);

	/**
	 * base64解密
	 * @param input         [in]  输入解密前数据
	 * @param input_len     [in]  输入解密前长度
	 * @param output        [out] 输出解密后数据（内存由函数内部malloc创建，需要调用者使用完毕后free释放）
	 * @param output_len    [out] 输出解密后长度
	 * @param with_new_line [in]  decode与encode时，with_new_line需保持一致
	 * @return true=成功，false=失败
	**/
	static bool base64_decode(
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool with_new_line = false);

	/**
	 * base64加密字符串
	 * @param input         [in]  输入加密前字符串
	 * @param output        [out] 输出加密后字符串
	 * @param with_new_line [in]  true=编码(encode)结果每64个字符换行一次，false=编码(encode)结果不换行
	 * @return true=成功，false=失败
	**/
	static bool base64_encode_str(
		const std::string& input,
		std::string& output,
		bool with_new_line = false);

	/**
	 * base64解密字符串
	 * @param input         [in]  输入解密前字符串
	 * @param output        [out] 输出解密后字符串
	 * @param with_new_line [in]  decode与encode时，with_new_line需保持一致
	 * @return true=成功，false=失败
	**/
	static bool base64_decode_str(
		const std::string& input,
		std::string& output,
		bool with_new_line = false);

public:
	/*************************************************************************
	** aes - 高级加密标准（Advanced Encryption Standard，AES）
	*************************************************************************/
	/**
	 * AES加密 模式:ECB，填充方式:PKCS7Padding，数据块:256位(32字节)
	 * @param key         [in]  密钥（长度必须是32字节，否则加密失败）
	 * @param input       [in]  输入加密前数据（参数padding: true=支持任意长度，false=只支持16字节的整数倍）
	 * @param output      [out] 输出加密后数据
	 * @param padding     [in]  是否填充（true=填充，false=不填充）注：若不填充，则应满足input数据长度是16字节的整数倍
	 * @param format_hex  [in]  加密后数据格式（true=十六进制字符串，false=base64编码不换行）
	 * @param toUppercase [in]  是否大写（true=大写，false=小写）注：仅当输出格式为十六进制时有效
	 * @return true=成功，false=失败
	**/
	static bool aes_256_ecb_encode_format(
		const std::string& key,
		const std::string& input,
		std::string& output,
		bool padding,
		bool format_hex,
		bool toUppercase = false);

	/**
	 * AES解密 模式:ECB，填充方式:PKCS7Padding，数据块:256位(32字节)
	 * @param key         [in]  密钥（长度必须是32字节，否则解密失败）
	 * @param input       [in]  输入解密前数据（长度必须是16字节的整数倍）
	 * @param output      [out] 输出解密后数据
	 * @param padding     [in]  解密前数据填充（true=填充，false=不填充）
	 * @param format_hex  [in]  解密前数据格式（true=十六进制字符串，false=base64编码不换行）
	 * @return true=成功，false=失败
	**/
	static bool aes_256_ecb_decode_format(
		const std::string& key,
		const std::string& input,
		std::string& output,
		bool padding,
		bool format_hex);

	/**
	 * AES加密 模式:ECB，填充方式:PKCS7Padding，数据块:256位(32字节)
	 * @param key        [in]  密钥（长度必须是32字节，否则加密失败）
	 * @param input      [in]  输入加密前数据（参数padding: true=支持任意长度，false=只支持16字节的整数倍）
	 * @param input_len  [in]  输入加密前长度
	 * @param output     [out] 输出加密后数据（内存由函数内部malloc创建，需要调用者使用完毕后free释放）
	 * @param output_len [out] 输出加密后长度
	 * @param padding    [in]  是否填充（true=填充，false=不填充）注：若不填充，则应满足input数据长度是16字节的整数倍
	 * @return true=成功，false=失败
	**/
	static bool aes_256_ecb_encode(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool padding);

	/**
	 * AES解密 模式:ECB，填充方式:PKCS7Padding，数据块:256位(32字节)
	 * @param key        [in]  密钥（长度必须是32字节，否则解密失败）
	 * @param input      [in]  输入解密前数据（长度必须是16字节的整数倍）
	 * @param input_len  [in]  输入解密前长度
	 * @param output     [out] 输出解密后数据（内存由函数内部malloc创建，需要调用者使用完毕后free释放）
	 * @param output_len [out] 输出解密后长度
	 * @param padding    [in]  解密前数据填充（true=填充，false=不填充）
	 * @return true=成功，false=失败
	**/
	static bool aes_256_ecb_decode(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool padding);

	/**
	 * AES加密 模式:ECB，填充方式:NoPadding，数据块:256位(32字节)
	 * @param key        [in]  密钥（长度必须是32字节，否则加密失败）
	 * @param input      [in]  输入加密前数据（长度必须是16字节的整数倍）
	 * @param input_len  [in]  输入加密前长度
	 * @param output_ptr [out] 输出加密后数据（指向的内存已开辟，且不小于input_len长度，加密后数据长度等于input_len）
	 * @return true=成功，false=失败
	**/
	static bool aes_256_ecb_encode_nopadding(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char* output_ptr);

	/**
	 * AES解密 模式:ECB，填充方式:NoPadding，数据块:256位(32字节)
	 * @param key        [in]  密钥（长度必须是32字节，否则解密失败）
	 * @param input      [in]  输入解密前数据（长度必须是16字节的整数倍）
	 * @param input_len  [in]  输入解密前长度
	 * @param output_ptr [out] 输出解密后数据（指向的内存已开辟，且不小于input_len长度，解密后数据长度等于input_len）
	 * @return true=成功，false=失败
	**/
	static bool aes_256_ecb_decode_nopadding(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char* output_ptr);

	/**
	 * AES加密 模式:OFB，填充方式:NoPadding，数据块:256位(32字节)
	 * @param key        [in]  密钥（长度必须是32字节，否则加密失败）
	 * @param input      [in]  输入加密前数据（支持任意长度）
	 * @param input_len  [in]  输入加密前长度
	 * @param output_ptr [out] 输出加密后数据（指向的内存已开辟，且不小于input_len长度，加密后数据长度等于input_len）
	 * @return true=成功，false=失败
	**/
	static bool aes_256_ofb_encode_nopadding(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char* output_ptr);

	/**
	 * AES解密 模式:OFB，填充方式:NoPadding，数据块:256位(32字节)
	 * @param key        [in]  密钥（长度必须是32字节，否则解密失败）
	 * @param input      [in]  输入解密前数据（支持任意长度）
	 * @param input_len  [in]  输入解密前长度
	 * @param output_ptr [out] 输出解密后数据（指向的内存已开辟，且不小于input_len长度，解密后数据长度等于input_len）
	 * @return true=成功，false=失败
	**/
	static bool aes_256_ofb_decode_nopadding(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char* output_ptr);

public:
	/*************************************************************************
	** rsa - 非对称加密算法
	*************************************************************************/
	/**
	 * 生成RSA密钥对（公钥与私钥）
	 * @param public_key  [out] 公钥（开头行："-----BEGIN PUBLIC KEY-----"， 结尾行："-----END PUBLIC KEY-----"， 中间内容每64个字符换行）
	 * @param private_key [out] 私钥（开头行："-----BEGIN PRIVATE KEY-----"，结尾行："-----END PRIVATE KEY-----"，中间内容每64个字符换行）
	 * @param key_bits    [in]  密钥长度（字节）
	 * @return true=成功，false=失败
	**/
	static bool generate_rsa_key(
		std::string& public_key,
		std::string& private_key,
		int key_bits = 1024);

	/**
	 * 序列化RSA密钥（去掉开头行与结尾行，拼接成一行）
	 * @param key_structured [in] 结构化的公钥或私钥（含有开头行与结尾行，中间内容每64个字符换行）
	 * @return 序列化密钥
	**/
	static std::string serialize_rsa_key(
		const std::string& key_structured);

	/**
	 * 结构化RSA公钥（添加开头行与结尾行，中间内容每64个字符换行）
	 * @param public_key_serialized  [in] 序列化的公钥
	 * @return 结构化公钥
	**/
	static std::string struct_public_key(
		const std::string& public_key_serialized);

	/**
	 * 结构化RSA私钥（添加开头行与结尾行，中间内容每64个字符换行）
	 * @param private_key_serialized [in] 序列化的私钥
	 * @return 结构化私钥
	**/
	static std::string struct_private_key(
		const std::string& private_key_serialized);

	/**
	 * 公钥加密 填充：RSA_PKCS1_PADDING，字符集：UTF8
	 * @param public_key  [in]  公钥（含有开头行与结尾行，中间内容每64个字符换行）
	 * @param input       [in]  加密前数据
	 * @param output      [out] 加密后数据（base64编码）
	 * @return true=成功，false=失败
	**/
	static bool rsa_public_key_encrypt(
		const std::string& public_key,
		const std::string& input,
		std::string& output);

	/**
	 * 公钥解密 填充：RSA_PKCS1_PADDING，字符集：UTF8
	 * @param public_key  [in]  公钥（含有开头行与结尾行，中间内容每64个字符换行）
	 * @param input       [in]  解密前数据（base64编码）
	 * @param output      [out] 解密后数据
	 * @return true=成功，false=失败
	**/
	static bool rsa_public_key_decrypt(
		const std::string& public_key,
		const std::string& input,
		std::string& output);

	/**
	 * 私钥加密 填充：RSA_PKCS1_PADDING，字符集：UTF8
	 * @param private_key [in]  私钥（含有开头行与结尾行，中间内容每64个字符换行）
	 * @param input       [in]  加密前数据
	 * @param output      [out] 加密后数据（base64编码）
	 * @return true=成功，false=失败
	**/
	static bool rsa_private_key_encrypt(
		const std::string& private_key,
		const std::string& input,
		std::string& output);

	/**
	 * 私钥解密 填充：RSA_PKCS1_PADDING，字符集：UTF8
	 * @param private_key [in]  私钥（含有开头行与结尾行，中间内容每64个字符换行）
	 * @param input       [in]  解密前数据（base64编码）
	 * @param output      [out] 解密后数据
	 * @return true=成功，false=失败
	**/
	static bool rsa_private_key_decrypt(
		const std::string& private_key,
		const std::string& input,
		std::string& output);
};
