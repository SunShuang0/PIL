#pragma once
#include <stdio.h>
#include "openssl/rsa.h"
#include "openssl/bn.h"
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

int zhuanhuan(int a);
void rsatest_genkey(BIGNUM* userPrivateKey, BIGNUM* userPublicKey);
void rsatest_ecrypt(BIGNUM* C, BIGNUM* M, BIGNUM* e, BIGNUM* n);
void rsatest_decrypt();

void rsatest(uint8_t* plaintext, uint8_t* ciphertext, BIGNUM* testPrivateKey, BIGNUM* testPublicKey);