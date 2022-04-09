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
	 * ʮ�������ַ�ת��Ϊ��ֵ
	**/
	static int hexchar_to_int(unsigned char ch);

	/**
	 * ʮ�������ַ���ת��Ϊ����
	 * @param input       [in]  ����ʮ�������ַ�������
	 * @param input_len   [in]  ����ʮ�������ַ�������
	 * @param output      [out] ������ݣ��ڴ��ɺ����ڲ�malloc��������Ҫ������ʹ����Ϻ�free�ͷţ�
	 * @param output_len  [out] �������
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool hexstr_to_buf(
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len);

	/**
	 * �ڴ�����ת��Ϊʮ�������ַ���
	 * @param input       [in]  �����ڴ�����
	 * @param input_len   [in]  �����ڴ泤��
	 * @param output      [out] ���ʮ�������ַ������ݣ��ڴ��ɺ����ڲ�malloc��������Ҫ������ʹ����Ϻ�free�ͷţ�
	 * @param output_len  [out] ���ʮ�������ַ�������
	 * @param toUppercase [in]  �Ƿ��д��true=��д��false=Сд��
	 * @return true=�ɹ���false=ʧ��
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
	 * �ڴ�����md5��ת��Ϊʮ�������ַ���
	 * @param input       [in]  �����ڴ�����
	 * @param input_len   [in]  �����ڴ泤��
	 * @param output      [out] ���md5��ʮ�������ַ������ݣ��ڴ��ɺ����ڲ�malloc��������Ҫ������ʹ����Ϻ�free�ͷţ�
	 * @param output_len  [out] ���md5��ʮ�������ַ������ȣ�32�ֽڣ�
	 * @param toUppercase [in]  �Ƿ��д��true=��д��false=Сд��
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool md5_buf_hex(
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool toUppercase);

	/**
	 * �ַ�������md5��ת��Ϊʮ�������ַ���
	 * @param input       [in]  �����ַ�������
	 * @param output      [out] ���md5��ʮ�������ַ������ݣ�32�ֽڣ�
	 * @param toUppercase [in]  �Ƿ��д��true=��д��false=Сд��
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool md5_str_hex(
		const std::string& input,
		std::string& output,
		bool toUppercase);

	/**
	 * �ļ�����md5��ת��Ϊʮ�������ַ���
	 * @param filepath    [in]  �ļ�·��
	 * @param output      [out] ���md5��ʮ�������ַ������ݣ�32�ֽڣ�
	 * @param toUppercase [in]  �Ƿ��д��true=��д��false=Сд��
	 * @return true=�ɹ���false=ʧ��
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
	 * base64����
	 * @param input         [in]  �������ǰ����
	 * @param input_len     [in]  �������ǰ����
	 * @param output        [out] ������ܺ����ݣ��ڴ��ɺ����ڲ�malloc��������Ҫ������ʹ����Ϻ�free�ͷţ�
	 * @param output_len    [out] ������ܺ󳤶�
	 * @param with_new_line [in]  true=����(encode)���ÿ64���ַ�����һ�Σ�false=����(encode)���������
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool base64_encode(
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool with_new_line = false);

	/**
	 * base64����
	 * @param input         [in]  �������ǰ����
	 * @param input_len     [in]  �������ǰ����
	 * @param output        [out] ������ܺ����ݣ��ڴ��ɺ����ڲ�malloc��������Ҫ������ʹ����Ϻ�free�ͷţ�
	 * @param output_len    [out] ������ܺ󳤶�
	 * @param with_new_line [in]  decode��encodeʱ��with_new_line�豣��һ��
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool base64_decode(
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool with_new_line = false);

	/**
	 * base64�����ַ���
	 * @param input         [in]  �������ǰ�ַ���
	 * @param output        [out] ������ܺ��ַ���
	 * @param with_new_line [in]  true=����(encode)���ÿ64���ַ�����һ�Σ�false=����(encode)���������
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool base64_encode_str(
		const std::string& input,
		std::string& output,
		bool with_new_line = false);

	/**
	 * base64�����ַ���
	 * @param input         [in]  �������ǰ�ַ���
	 * @param output        [out] ������ܺ��ַ���
	 * @param with_new_line [in]  decode��encodeʱ��with_new_line�豣��һ��
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool base64_decode_str(
		const std::string& input,
		std::string& output,
		bool with_new_line = false);

public:
	/*************************************************************************
	** aes - �߼����ܱ�׼��Advanced Encryption Standard��AES��
	*************************************************************************/
	/**
	 * AES���� ģʽ:ECB����䷽ʽ:PKCS7Padding�����ݿ�:256λ(32�ֽ�)
	 * @param key         [in]  ��Կ�����ȱ�����32�ֽڣ��������ʧ�ܣ�
	 * @param input       [in]  �������ǰ���ݣ�����padding: true=֧�����ⳤ�ȣ�false=ֻ֧��16�ֽڵ���������
	 * @param output      [out] ������ܺ�����
	 * @param padding     [in]  �Ƿ���䣨true=��䣬false=����䣩ע��������䣬��Ӧ����input���ݳ�����16�ֽڵ�������
	 * @param format_hex  [in]  ���ܺ����ݸ�ʽ��true=ʮ�������ַ�����false=base64���벻���У�
	 * @param toUppercase [in]  �Ƿ��д��true=��д��false=Сд��ע�����������ʽΪʮ������ʱ��Ч
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool aes_256_ecb_encode_format(
		const std::string& key,
		const std::string& input,
		std::string& output,
		bool padding,
		bool format_hex,
		bool toUppercase = false);

	/**
	 * AES���� ģʽ:ECB����䷽ʽ:PKCS7Padding�����ݿ�:256λ(32�ֽ�)
	 * @param key         [in]  ��Կ�����ȱ�����32�ֽڣ��������ʧ�ܣ�
	 * @param input       [in]  �������ǰ���ݣ����ȱ�����16�ֽڵ���������
	 * @param output      [out] ������ܺ�����
	 * @param padding     [in]  ����ǰ������䣨true=��䣬false=����䣩
	 * @param format_hex  [in]  ����ǰ���ݸ�ʽ��true=ʮ�������ַ�����false=base64���벻���У�
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool aes_256_ecb_decode_format(
		const std::string& key,
		const std::string& input,
		std::string& output,
		bool padding,
		bool format_hex);

	/**
	 * AES���� ģʽ:ECB����䷽ʽ:PKCS7Padding�����ݿ�:256λ(32�ֽ�)
	 * @param key        [in]  ��Կ�����ȱ�����32�ֽڣ��������ʧ�ܣ�
	 * @param input      [in]  �������ǰ���ݣ�����padding: true=֧�����ⳤ�ȣ�false=ֻ֧��16�ֽڵ���������
	 * @param input_len  [in]  �������ǰ����
	 * @param output     [out] ������ܺ����ݣ��ڴ��ɺ����ڲ�malloc��������Ҫ������ʹ����Ϻ�free�ͷţ�
	 * @param output_len [out] ������ܺ󳤶�
	 * @param padding    [in]  �Ƿ���䣨true=��䣬false=����䣩ע��������䣬��Ӧ����input���ݳ�����16�ֽڵ�������
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool aes_256_ecb_encode(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool padding);

	/**
	 * AES���� ģʽ:ECB����䷽ʽ:PKCS7Padding�����ݿ�:256λ(32�ֽ�)
	 * @param key        [in]  ��Կ�����ȱ�����32�ֽڣ��������ʧ�ܣ�
	 * @param input      [in]  �������ǰ���ݣ����ȱ�����16�ֽڵ���������
	 * @param input_len  [in]  �������ǰ����
	 * @param output     [out] ������ܺ����ݣ��ڴ��ɺ����ڲ�malloc��������Ҫ������ʹ����Ϻ�free�ͷţ�
	 * @param output_len [out] ������ܺ󳤶�
	 * @param padding    [in]  ����ǰ������䣨true=��䣬false=����䣩
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool aes_256_ecb_decode(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char** output,
		size_t* output_len,
		bool padding);

	/**
	 * AES���� ģʽ:ECB����䷽ʽ:NoPadding�����ݿ�:256λ(32�ֽ�)
	 * @param key        [in]  ��Կ�����ȱ�����32�ֽڣ��������ʧ�ܣ�
	 * @param input      [in]  �������ǰ���ݣ����ȱ�����16�ֽڵ���������
	 * @param input_len  [in]  �������ǰ����
	 * @param output_ptr [out] ������ܺ����ݣ�ָ����ڴ��ѿ��٣��Ҳ�С��input_len���ȣ����ܺ����ݳ��ȵ���input_len��
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool aes_256_ecb_encode_nopadding(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char* output_ptr);

	/**
	 * AES���� ģʽ:ECB����䷽ʽ:NoPadding�����ݿ�:256λ(32�ֽ�)
	 * @param key        [in]  ��Կ�����ȱ�����32�ֽڣ��������ʧ�ܣ�
	 * @param input      [in]  �������ǰ���ݣ����ȱ�����16�ֽڵ���������
	 * @param input_len  [in]  �������ǰ����
	 * @param output_ptr [out] ������ܺ����ݣ�ָ����ڴ��ѿ��٣��Ҳ�С��input_len���ȣ����ܺ����ݳ��ȵ���input_len��
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool aes_256_ecb_decode_nopadding(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char* output_ptr);

	/**
	 * AES���� ģʽ:OFB����䷽ʽ:NoPadding�����ݿ�:256λ(32�ֽ�)
	 * @param key        [in]  ��Կ�����ȱ�����32�ֽڣ��������ʧ�ܣ�
	 * @param input      [in]  �������ǰ���ݣ�֧�����ⳤ�ȣ�
	 * @param input_len  [in]  �������ǰ����
	 * @param output_ptr [out] ������ܺ����ݣ�ָ����ڴ��ѿ��٣��Ҳ�С��input_len���ȣ����ܺ����ݳ��ȵ���input_len��
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool aes_256_ofb_encode_nopadding(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char* output_ptr);

	/**
	 * AES���� ģʽ:OFB����䷽ʽ:NoPadding�����ݿ�:256λ(32�ֽ�)
	 * @param key        [in]  ��Կ�����ȱ�����32�ֽڣ��������ʧ�ܣ�
	 * @param input      [in]  �������ǰ���ݣ�֧�����ⳤ�ȣ�
	 * @param input_len  [in]  �������ǰ����
	 * @param output_ptr [out] ������ܺ����ݣ�ָ����ڴ��ѿ��٣��Ҳ�С��input_len���ȣ����ܺ����ݳ��ȵ���input_len��
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool aes_256_ofb_decode_nopadding(
		const unsigned char* key,
		const unsigned char* input,
		const size_t input_len,
		unsigned char* output_ptr);

public:
	/*************************************************************************
	** rsa - �ǶԳƼ����㷨
	*************************************************************************/
	/**
	 * ����RSA��Կ�ԣ���Կ��˽Կ��
	 * @param public_key  [out] ��Կ����ͷ�У�"-----BEGIN PUBLIC KEY-----"�� ��β�У�"-----END PUBLIC KEY-----"�� �м�����ÿ64���ַ����У�
	 * @param private_key [out] ˽Կ����ͷ�У�"-----BEGIN PRIVATE KEY-----"����β�У�"-----END PRIVATE KEY-----"���м�����ÿ64���ַ����У�
	 * @param key_bits    [in]  ��Կ���ȣ��ֽڣ�
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool generate_rsa_key(
		std::string& public_key,
		std::string& private_key,
		int key_bits = 1024);

	/**
	 * ���л�RSA��Կ��ȥ����ͷ�����β�У�ƴ�ӳ�һ�У�
	 * @param key_structured [in] �ṹ���Ĺ�Կ��˽Կ�����п�ͷ�����β�У��м�����ÿ64���ַ����У�
	 * @return ���л���Կ
	**/
	static std::string serialize_rsa_key(
		const std::string& key_structured);

	/**
	 * �ṹ��RSA��Կ����ӿ�ͷ�����β�У��м�����ÿ64���ַ����У�
	 * @param public_key_serialized  [in] ���л��Ĺ�Կ
	 * @return �ṹ����Կ
	**/
	static std::string struct_public_key(
		const std::string& public_key_serialized);

	/**
	 * �ṹ��RSA˽Կ����ӿ�ͷ�����β�У��м�����ÿ64���ַ����У�
	 * @param private_key_serialized [in] ���л���˽Կ
	 * @return �ṹ��˽Կ
	**/
	static std::string struct_private_key(
		const std::string& private_key_serialized);

	/**
	 * ��Կ���� ��䣺RSA_PKCS1_PADDING���ַ�����UTF8
	 * @param public_key  [in]  ��Կ�����п�ͷ�����β�У��м�����ÿ64���ַ����У�
	 * @param input       [in]  ����ǰ����
	 * @param output      [out] ���ܺ����ݣ�base64���룩
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool rsa_public_key_encrypt(
		const std::string& public_key,
		const std::string& input,
		std::string& output);

	/**
	 * ��Կ���� ��䣺RSA_PKCS1_PADDING���ַ�����UTF8
	 * @param public_key  [in]  ��Կ�����п�ͷ�����β�У��м�����ÿ64���ַ����У�
	 * @param input       [in]  ����ǰ���ݣ�base64���룩
	 * @param output      [out] ���ܺ�����
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool rsa_public_key_decrypt(
		const std::string& public_key,
		const std::string& input,
		std::string& output);

	/**
	 * ˽Կ���� ��䣺RSA_PKCS1_PADDING���ַ�����UTF8
	 * @param private_key [in]  ˽Կ�����п�ͷ�����β�У��м�����ÿ64���ַ����У�
	 * @param input       [in]  ����ǰ����
	 * @param output      [out] ���ܺ����ݣ�base64���룩
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool rsa_private_key_encrypt(
		const std::string& private_key,
		const std::string& input,
		std::string& output);

	/**
	 * ˽Կ���� ��䣺RSA_PKCS1_PADDING���ַ�����UTF8
	 * @param private_key [in]  ˽Կ�����п�ͷ�����β�У��м�����ÿ64���ַ����У�
	 * @param input       [in]  ����ǰ���ݣ�base64���룩
	 * @param output      [out] ���ܺ�����
	 * @return true=�ɹ���false=ʧ��
	**/
	static bool rsa_private_key_decrypt(
		const std::string& private_key,
		const std::string& input,
		std::string& output);
};
