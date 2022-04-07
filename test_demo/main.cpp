// main.cpp : Defines the entry point for the console application.
//

#include <SDKDDKVer.h>
#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include "tests.h"

int main()
{
	tests::test_memcpy_ull();
	tests::test_hex();
	tests::test_md5();
	tests::test_base64();
	tests::test_aes_256_ecb();
	tests::test_rsa();

	system("pause");
	return 0;
}
