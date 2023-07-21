#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <memory.h>
#include "sm4gcm/sm4.h"
#include "sm4gcm/mode.h"
#include "sm4gcm/err.h"
#include "sm4gcm/utils.h"
#include "openssl/ssl.h"
#include "openssl/sha.h"
#include "openssl/rsa.h"
#include "openssl/bn.h"


//unsigned int a = 0x44332211;
//printf("0x%x的第0个字节为：0x%x\n", a, GET_LOW_BYTE0(a));
//printf("0x%x的第1个字节为：0x%x\n", a, GET_LOW_BYTE1(a));
//printf("0x%x的第2个字节为：0x%x\n", a, GET_LOW_BYTE2(a));
//printf("0x%x的第3个字节为：0x%x\n", a, GET_LOW_BYTE3(a));
const unsigned char* strprivate = "2AC29DA2B7FF520139F751D9E5074B8C1193A35AEB4C866665C99ED9CDBD87AE96F8A883E0C231B5465492EEAD3102FF9E646E5B3797F21213CDAF9FCA857BA126E48262485DA3A09C1121198E188D6E5251D70C0F748AB26B683254584356277676C8C8A7CD58556225AE7F6B6B55493537B1B54FD5A4C43D680307E9548B51";
const unsigned char* strpublic = "F1D597AAF03A309D3469F2C59081BC628DE94F6909F925172807E0F869D96A38593BFD72FE7485C6BD25958039414EBFC9A7BCD545F7E82F7EA0053F0DA2FF2EA004C5868E72B54D9372B998CAAFCC329A024C8E00AFFD49FD5DC7C0FAAFB601CFFBD8ADA8988747EA9AD8246A44A83345BF34F229A3E9A3DC3676B4863FDFC9";
int count = 0;
int flag = 0;
// x,y0,y1共12字节，F0,F1,F2,F3共32字节，加上Proof1长度为128，共172
uint8_t aliceToBob[44] = { 0x00 };
uint8_t* send;
// D0,D1,D2,D3共32字节，加上Proof1长度为128，共160
uint8_t bobToAlice[160] = { 0x00 };


uint8_t Server_PublicKey[8] = { 0x00 };
uint8_t Server_PrivateKey[8] = { 0x00 };
uint8_t Client_PublicKey[8] = { 0x00 };
uint8_t Client_PrivateKey[8] = { 0x00 };
uint8_t Verifier_PublicKey[8] = { 0x00 };
uint8_t Verifier_PrivateKey[8] = { 0x00 };
uint8_t x0[4] = { 0x00 };
uint8_t x1[4] = { 0x00 };
uint8_t yy0[4] = { 0x00 };
uint8_t yy1[4] = { 0x00 };
uint8_t z0[4] = { 0x00 };
uint8_t z1[4] = { 0x00 };
uint8_t seed[4] = { 0x00 };
uint8_t HashSeed[32] = { 0x00 };
uint8_t ProofS[100] = { 0x00 };
uint8_t layer1[24] = { 0x00 };

uint8_t x[4] = { 0x00 };
uint8_t y[4] = { 0x00 };
uint8_t z[4] = { 0x00 };
uint8_t Result[4] = { 0x00 };
uint8_t u = 0;
uint8_t v = 0;
uint8_t f0[8] = { 0x00 };
uint8_t f1[8] = { 0x00 };
uint8_t f2[8] = { 0x00 };
uint8_t f3[8] = { 0x00 };
uint8_t H0[8] = { 0x00 };
uint8_t H1[8] = { 0x00 };
uint8_t H2[8] = { 0x00 };
uint8_t H3[8] = { 0x00 };

uint8_t DeOutput12[4] = { 0x00 };
uint8_t DeOutput22[4] = { 0x00 };
uint8_t DeOutput32[4] = { 0x00 };
uint8_t DeOutput42[4] = { 0x00 };

/* SM4 Part Begin */
extern const CipherInfo SM4Info;
static uint8_t gcm_iv_A[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
static uint8_t gcm_aad_A[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b,
    0xdb, 0x37, 0x0c, 0x43, 0x7f, 0xec, 0x78, 0xde,
};
static uint8_t en_out_A[SM4_BLOCK_SIZE * 4];
static int en_outlen_A;
static uint8_t en_tag_A[SM4_BLOCK_SIZE];
static int en_taglen_A = SM4_BLOCK_SIZE;
/* SM4 Part End */

