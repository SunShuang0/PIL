#pragma warning(disable:4996)
#define _CRT_SECURE_NO_WARNINGS
#define	GET_BIT(x, bit)	((x & (1 << bit)) >> bit)	/* 获取第bit位 */
#define BIT_M_TO_N(x, m, n)  ((unsigned int)(x << (31-(n))) >> ((31 - (n)) + (m)))		/* 获取第[n:m]位的值 */
#include "main.h"
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")


// Basic Function - sha256
int mysha256(const char* readstr, unsigned char* md)
{
	if (SHA256((unsigned char*)readstr, strlen(readstr), md) == NULL) {
		printf("sha256 erro\n");
		return -1;
	}
	return 0;
}
void printf256(unsigned char* md)
{
	for (int i = 0; i < 32; i++) {
		//printf("%02X ", md[i]);
	}
	//printf("\n");
}

// Basic Function - SM4 Encryption
void SM4_encrypt(uint8_t* key, uint8_t* EnInput, int plain_len, uint8_t* EnOutput)
{
	GCM_CTX en_ctx;
	SM4_CTX sm4_en_ctx;
	uint8_t* en_outptr;
	const CipherInfo* cipher = &SM4Info;

	en_outptr = en_out_A;
	gcm_init(key, gcm_iv_A, sizeof(gcm_iv_A), NULL, cipher, &sm4_en_ctx, &en_ctx);
	gcm_encrypt_update(en_outptr, &en_outlen_A, EnInput, plain_len, &en_ctx);
	en_outptr += en_outlen_A;
	gcm_encrypt_final(en_outptr, &en_outlen_A, en_tag_A, en_taglen_A, &en_ctx);
	en_outptr += en_outlen_A;

	// printf("\nEncrypt Result:");
	for (int i = 0; i < plain_len; i++)
	{
		EnOutput[i] = en_out_A[i];
		// printf("%#04X ", EnOutput[i]);
	}
	printf("\n");
	//printf("\nTag in A:");
	//for (int i = 0; i < 16; i++)
	//{
	//	printf("%#04X ", en_tag_A[i]);
	//}
	//printf("\n");
}
// decryptB(yb, cipher, 8, fb0, DeOutput11);
//    密钥，结构体，密文长度，密文，明文
void SM4_decrypt(uint8_t* key, CipherInfo* cipher, int cipherSize, uint8_t* DeInput, uint8_t* DeOutput)
{
	uint8_t de_out[SM4_BLOCK_SIZE * 4];
	int de_outlen;
	uint8_t de_tag[SM4_BLOCK_SIZE];
	int de_taglen = SM4_BLOCK_SIZE;
	GCM_CTX de_ctx;
	SM4_CTX sm4_de_ctx;
	uint8_t* de_outptr;
	de_outptr = de_out;

	gcm_init(key, gcm_iv_A, sizeof(gcm_iv_A), NULL, cipher, &sm4_de_ctx, &de_ctx);
	gcm_decrypt_update(de_outptr, &de_outlen, DeInput, cipherSize, &de_ctx);
	de_outptr += de_outlen;
	int err = gcm_decrypt_final(de_outptr, &de_outlen, DeInput + cipherSize, de_taglen, &de_ctx);
	de_outptr += de_outlen;

	//printf("plaintext:\n");
	for (size_t i = 0; i < cipherSize; i++)
	{
		DeOutput[i] = de_out[i];
		// printf("%#04x ", de_out[i]);
	}
	//printf("\n");
	// printf("\n\nTag Err = %d\n\n", err);
}

// Basic Function - get 2 bits and transfer them to decimal value
uint8_t getN2Mbits2Decimal(uint8_t inputNumber, uint8_t begin, uint8_t length)
{
	uint8_t decimalValue = 0;
	uint8_t result = 0;

	result = BIT_M_TO_N(inputNumber, begin, begin + 1);
	switch (result)
	{
	case 0:
		decimalValue = 0;
		// printf("bit[%d,%d]位是：00，十进制值为%d\n", begin, begin + 1, decimalValue);
		break;
	case 1:
		decimalValue = 1;
		// printf("bit[%d,%d]位是：01，十进制值为%d\n", begin, begin + 1, decimalValue);
		break;
	case 2:
		decimalValue = 2;
		// printf("bit[%d,%d]位是：10，十进制值为%d\n", begin, begin + 1, decimalValue);
		break;
	case 3:
		decimalValue = 3;
		// printf("bit[%d,%d]位是：11，十进制值为%d\n", begin, begin + 1, decimalValue);
		break;
	}
	return decimalValue;
}

uint8_t* int2hex(int number, uint8_t * hexString, int i)
{
	if (number < 16)
	{
		if (number < 10)
		{
			hexString[i] = number + '0';
		}
		else
		{
			hexString[i] = number - 10 + 'A';
		}
		hexString[i + 1] = '\0';
	}
	else
	{
		int2hex(number / 16, hexString, i);
		i++;
		number %= 16;
		if (number < 10)
		{
			hexString[i] = number + '0';
		}
		else
		{
			hexString[i] = number - 10 + 'A';
		}
	}
}

/* 1.1 Generate the pesudo-random function - GenPRF() */
void GenPRF()
{
	// 1. Random out a seed, then compute its hash value
	//printf("SEED in this round : ");
	srand(time(NULL));
	for (size_t i = 0; i < 4; i++)
	{
		seed[i] = rand() % 9;
		//printf("%#04X ", seed[i]);
	}
	//printf("\n");
	memset(HashSeed, 0, 32);
	mysha256(seed, HashSeed);
	// printf("Hash value in SHA256: ");
	// printf256(HashSeed);

	// 2. Random out 6 values for x0, x1, y0, y1, z0, z1
	srand(time(NULL));
	for (size_t i = 0; i < 4; i++)
	{
		x0[i] = rand() % 256;
		x1[i] = rand() % 256;
		yy0[i] = rand() % 256;
		yy1[i] = rand() % 256;
		z0[i] = rand() % 256;
		z1[i] = rand() % 256;
	}

	// printf("\nRandom Numbers:\nx0: ");
	//for (size_t i = 0; i < 4; i++)
	//{

	//	printf("%#04X ", x[i]);
	//}
	//printf("x0: ");
	for (size_t i = 0; i < 4; i++)
	{

		// printf("%#04X ", x0[i]);
	}
	// printf("\nx1: ");
	for (size_t i = 0; i < 4; i++)
	{

		// printf("%#04X ", x1[i]);
	}
	// printf("\ny0: ");
	for (size_t i = 0; i < 4; i++)
	{

		// printf("%#04X ", yy0[i]);
	}
	// printf("\ny1: ");
	for (size_t i = 0; i < 4; i++)
	{

		// printf("%#04X ", yy1[i]);
	}
	// printf("\nz0: ");
	for (size_t i = 0; i < 4; i++)
	{

		// printf("%#04X ", z0[i]);
	}
	// printf("\nz1: ");
	for (size_t i = 0; i < 4; i++)
	{

		// printf("%#04X ", z1[i]);
	}

	// 3. Generate random factors u, v
	uint8_t u0 = ( HashSeed[0] & 0xf0 ) >> 4;	// high 4 bits
	uint8_t u1 = HashSeed[31] & 0x0f;			// low 4 bits
	uint8_t u2 = HashSeed[16];
	uint8_t u3 = HashSeed[17];
	// printf("\n\nu0 = %#04X, u1 = %#04X, u2 = %#04X, u3 = %#04X\n\n", u0, u1, u2, u3);
	u = (u0 | u2) ^ (u1 | u3);
	v = (u0 | u3) & (u1 | u2);
	// printf("Random Factors in this round :\nu = %d, v = %d\n", u, v);

	// 4. Generate the pesudo-random function
	if ((uint8_t)u > (uint8_t)v)
	{
		// printf("\n(u > v)\nPseudo-Random Function in this round:\n");
		for (size_t i = 0; i < 4; i++)
		{
			x[i] = x0[i];
			layer1[i] = x[i];
			// 当 x = x0 时，第一对(y,z)是(y0,z1)
			layer1[4 + i] = yy0[i];
			layer1[8 + i] = z1[i];
			// 第二对是(y1,z0)
			layer1[12 + i] = yy1[i];
			layer1[16 + i] = z0[i];
			// z0的值代表抽中，拼接在最后
			layer1[20 + i] = z0[i];
		}
		
		if ( x == x0 && y == yy0 )
		{
			// printf("\nWhen x == x0 && y == y0, f(x) = ");
			for (size_t i = 0; i < 4; i++)
			{
				z[i] = z1[i];
				// printf("%#04X ", z[i]);
			}
		} else {
			// printf("\nWhen x != x0 || y != y0, f(x) = ");
			for (size_t i = 0; i < 4; i++)
			{
				z[i] = z0[i];
				// printf("%#04X ", z[i]);
			}
		}
		// printf("\n\n");

	}
	else
	{
		// printf("\n(u <= v)\nPseudo-Random Function in this round:\n");
		for (size_t i = 0; i < 4; i++)
		{
			x[i] = x1[i];
			layer1[i] = x[i];
			// 当 x = x1 时，第一对(y,z)是(y1,z1)
			layer1[4 + i] = yy1[i];
			layer1[8 + i] = z1[i];
			// 第二对是(y0,z0)
			layer1[12 + i] = yy0[i];
			layer1[16 + i] = z0[i];
			// z0的值代表抽中，拼接在最后
			layer1[20 + i] = z0[i];
		}

		if (x == x1 && y == yy1)
		{
			// printf("\nWhen x == x1 && y == y1, f(x) = ");
			for (size_t i = 0; i < 4; i++)
			{
				z[i] = z1[i];
				// printf("%#04X ", z[i]);
			}
		}
		else
		{
			// printf("\nWhen x != x1 || y != y1, f(x) = ");
			for (size_t i = 0; i < 4; i++)
			{
				z[i] = z0[i];
				// printf("%#04X ", z[i]);
			}
		}
	}

	for (int i = 0; i < 4; i++)
	{
		aliceToBob[i] = x[i];
		aliceToBob[4 + i] = yy0[i];
		aliceToBob[8 + i] = yy1[i];
	}
	
	// printf("\n");

}

void garbledSequence(uint8_t h, uint8_t* H)
{
	switch (h)
	{
	case 0:
		for (size_t i = 0; i < 8; i++)
		{
			H[i] = f0[i];
		}
		break;
	case 1:
		for (size_t i = 0; i < 8; i++)
		{
			H[i] = f1[i];
		}
		break;
	case 2:
		for (size_t i = 0; i < 8; i++)
		{
			H[i] = f2[i];
		}
		break;
	case 3:
		for (size_t i = 0; i < 8; i++)
		{
			H[i] = f3[i];
		}
		break;
	default:
		break;
	}
}

/* 1.2 Generate the grabled sequence - GenGValues() */
void GenGValues()
{
	// 1. Generate garbled value based on (u,v)/pesudo-random number
	if ((uint8_t)u > (uint8_t)v)
	{
		uint8_t EnOutput1[8] = { 0x00 };
		SM4_encrypt(x0, z1, 8, EnOutput1);
		SM4_encrypt(yy0, EnOutput1, 8, f0);
		

		uint8_t EnOutput2[8] = { 0x00 };
		SM4_encrypt(x0, z0, 8, EnOutput2);
		SM4_encrypt(yy1, EnOutput2, 8, f1);
	

		uint8_t EnOutput3[8] = { 0x00 };
		SM4_encrypt(x1, z0, 8, EnOutput3);
		SM4_encrypt(yy0, EnOutput3, 8, f2);

		uint8_t EnOutput4[8] = { 0x00 };
		SM4_encrypt(x1, z0, 8, EnOutput4);
		SM4_encrypt(yy1, EnOutput4, 8, f3);

	}
	else
	{
		uint8_t EnOutput1[8] = { 0x00 };
		SM4_encrypt(x0, z0, 8, EnOutput1);
		SM4_encrypt(yy0, EnOutput1, 8, f0);

		uint8_t EnOutput2[8] = { 0x00 };
		SM4_encrypt(x0, z0, 8, EnOutput2);
		SM4_encrypt(yy1, EnOutput2, 8, f1);

		uint8_t EnOutput3[8] = { 0x00 };
		SM4_encrypt(x1, z0, 8, EnOutput3);
		SM4_encrypt(yy0, EnOutput3, 8, f2);

		uint8_t EnOutput4[8] = { 0x00 };
		SM4_encrypt(x1, z1, 8, EnOutput4);
		SM4_encrypt(yy1, EnOutput4, 8, f3);
	}

	// 2. Generate h0, h1, h2, h3
	uint8_t h0 = getN2Mbits2Decimal((uint8_t)(HashSeed[8]), 0, 2);
	uint8_t h1 = getN2Mbits2Decimal( (uint8_t)(HashSeed[8]), 2, 2);
	uint8_t h2 = getN2Mbits2Decimal( (uint8_t)(HashSeed[8]), 4, 2);
	uint8_t h3 = getN2Mbits2Decimal( (uint8_t)(HashSeed[8]), 6, 2);
	while (h1 == h0)
	{
		h1 = (h1 + 1) % 4;
	}
	while (h2 == h1 || h2 == h0)
	{
		h2 = (h2 + 1) % 4;
	}
	while (h3 == h2 || h3 == h1 || h3 == h0)
	{
		h3 = (h3 + 1) % 4;
	}
	// printf("\nh0 = %d, h1 = %d, h2 = %d, h3 = %d\n", h0, h1, h2, h3);

	// 3. Generate garbled sequence
	garbledSequence(h0, H0);
	garbledSequence(h1, H1);
	garbledSequence(h2, H2);
	garbledSequence(h3, H3);
	// printf("\nGarbled Sequence：\n");
	// printf("F0:");
	for (int i = 0; i < 8; i++)
	{
		aliceToBob[12 + i] = H0[i];
		// printf("%#04X ", H0[i]);
	}
	// printf("\nF1:");
	for (int i = 0; i < 8; i++)
	{
		aliceToBob[20 + i] = H1[i];
		// printf("%#04X ", H1[i]);
	}
	// printf("\nF2:");
	for (int i = 0; i < 8; i++)
	{
		aliceToBob[28 + i] = H2[i];
		// printf("%#04X ", H2[i]);
	}
	// printf("\nF3:");
	for (int i = 0; i < 8; i++)
	{
		aliceToBob[36 + i] = H3[i];
		// printf("%#04X ", H3[i]);
	}
	
}

/* 1.3 验证值生成 - Proof1() */
void Proof1(BIGNUM* alicePublicKey, BIGNUM* carolPublicKey, BIGNUM* e, BIGNUM* C, BIGNUM* C2)
{
	// printf("\n\nSplicing Parameters:\n");
	for (size_t i = 0; i < 24; i++)
	{
		// printf("%#04X ", layer1[i]);
	}

	// 第一次加密 Alice Public Key
	
	BIGNUM* M = BN_new();
	BN_bin2bn(layer1, 24, M);
	rsatest_ecrypt(C, M, e, alicePublicKey);
	// printf("\n\nInternal Encryption：\n%s\n", BN_bn2hex(C));

	// 第二次加密 Carol Public Key
	
	BIGNUM* M2 = BN_new();
	// BN_bin2bn(C, 128, M2);
	rsatest_ecrypt(C2, C, e, carolPublicKey);
	// printf("\n\nExternal Encryption:\nPROOFS =\n%s\n", BN_bn2hex(C2));
	send = BN_bn2hex(C2);
}


/* ===============  2 计算 ===============  */
/* 2.1 混淆电路计算 */
void computGC()
{
	// parse token aliceToBob[44]
	uint8_t xb[4] = { 0x00 };
	uint8_t yb[4] = { 0x00 };
	uint8_t yb0[4] = { 0x00 };
	uint8_t yb1[4] = { 0x00 };
	uint8_t fb0[8] = { 0x00 };
	uint8_t fb1[8] = { 0x00 };
	uint8_t fb2[8] = { 0x00 };
	uint8_t fb3[8] = { 0x00 };
	// printf("x = ");
	for (size_t i = 0; i < 4; i++)
	{
		xb[i] = aliceToBob[i];
		yb0[i] = aliceToBob[4 + i];
		yb0[i] = aliceToBob[8 + i];
		// printf("%#04X ", xb[i]);
	}
	// printf("\n");
	for (size_t i = 0; i < 8; i++)
	{
		fb0[i] = aliceToBob[12 + i];
		fb1[i] = aliceToBob[20 + i];
		fb2[i] = aliceToBob[28 + i];
		fb3[i] = aliceToBob[36 + i];
		// // printf("fb0[%d] = %#04X, fb1[%d] = %#04X, fb2[%d] = %#04X, fb3[%d] = %#04X\n", i, fb0[i], i, fb1[i], i, fb2[i], i, fb3[i] );
	}
	

	// 2. Random out a seed, then compute its hash value
	// printf("SEED' in this round : ");
	srand(time(NULL));
	for (size_t i = 0; i < 4; i++)
	{
		seed[i] = rand() % 9;
		// printf("%#04X ", seed[i]);
	}
	// printf("\n");
	memset(HashSeed, 0, 32);
	mysha256(seed, HashSeed);
	// printf("Hash value in SHA256: ");
	printf256(HashSeed);

	// 3. Generate random factors u, v
	uint8_t u0 = (HashSeed[0] & 0xf0) >> 4;	// high 4 bits
	uint8_t u1 = HashSeed[31] & 0x0f;			// low 4 bits
	uint8_t u2 = HashSeed[16];
	uint8_t u3 = HashSeed[17];
	// printf("\nu0 = %#04X, u1 = %#04X, u2 = %#04X, u3 = %#04X\n", u0, u1, u2, u3);
	u = (u0 | u2) ^ (u1 | u3);
	v = (u0 | u3) & (u1 | u2);
	// printf("Random Factors in this round :\nu = %d, v = %d\n", u, v);

	// 4. Determin y
	// printf("y = ");
	if ((uint8_t)u > (uint8_t)v)
	{
		for (size_t i = 0; i < 4; i++)
		{
			yb[i] = yb0[i];
			// printf("%#04X ", yb[i]);
		}
	} else {
		for (size_t i = 0; i < 4; i++)
		{
			yb[i] = yb1[i];
			// printf("%#04X ", yb[i]);
		}
	}
	// printf("\n\n");

	// Decrypt garbled sequence
	const CipherInfo* cipher11 = &SM4Info;
	uint8_t DeOutput11[8] = { 0x00 };
	SM4_decrypt(yy0, cipher11, 8, fb0, DeOutput11);
	SM4_decrypt(x0, cipher11, 4, DeOutput11, DeOutput12);
	// printf("D0: ");
	for (size_t i = 0; i < 4; i++)
	{
		bobToAlice[i] = DeOutput12[i];
		// printf("%#04x ", DeOutput12[i]);
	}
	// printf("\n");

	const CipherInfo* cipher21 = &SM4Info;
	uint8_t DeOutput21[8] = { 0x00 };
	SM4_decrypt(yy0, cipher21, 8, fb1, DeOutput21);
	SM4_decrypt(x0, cipher21, 4, DeOutput21, DeOutput22);
	// printf("D1: ");
	for (size_t i = 0; i < 4; i++)
	{
		bobToAlice[8+i] = DeOutput22[i];
		// printf("%#04x ", DeOutput22[i]);
	}
	// printf("\n");

	const CipherInfo* cipher31 = &SM4Info;
	uint8_t DeOutput31[8] = { 0x00 };
	SM4_decrypt(yy0, cipher31, 8, fb2, DeOutput31);
	SM4_decrypt(x0, cipher31, 4, DeOutput31, DeOutput32);
	// printf("D2: ");
	for (size_t i = 0; i < 4; i++)
	{
		bobToAlice[16+i] = DeOutput32[i];
		// printf("%#04x ", DeOutput32[i]);
	}
	// printf("\n");

	const CipherInfo* cipher41 = &SM4Info;
	uint8_t DeOutput41[8] = { 0x00 };
	SM4_decrypt(yy0, cipher41, 8, fb3, DeOutput41);
	SM4_decrypt(x0, cipher41, 4, DeOutput41, DeOutput42);
	// printf("D3: ");
	for (size_t i = 0; i < 4; i++)
	{
		bobToAlice[24+i] = DeOutput42[i];
		// printf("%#04x ", DeOutput42[i]);
	}
	// printf("\n");

	// printf("\n");
}
/* 2.2 验证值生成 */
void proof2(BIGNUM* bobPublicKey, BIGNUM* carolPublicKey, BIGNUM* e, BIGNUM* C4, BIGNUM* C6)
{
	// 第一次加密 Bob Public Key
	// BIGNUM* C = BN_new();
	BIGNUM* M = BN_new();
	BN_bin2bn(send, 128, M);
	rsatest_ecrypt(C4, M, e, bobPublicKey);
	// printf("\n\nInternal Encryption：\n%s\n", BN_bn2hex(C4));

	// 第二次加密 Carol Public Key
	// BIGNUM* C2 = BN_new();
	BIGNUM* M2 = BN_new();
	// BN_bin2bn(C, 128, M2);
	rsatest_ecrypt(C6, C4, e, carolPublicKey);
	// printf("\n\nExternal Encryption:\nPROOF =\n%s\n", BN_bn2hex(C6));
}
/* ===============  3 抽取 ===============  */
void lottery()
{
	flag = 0;
	for (size_t i = 0; i < 4; i++)
	{
		if (DeOutput12[i] == z1[i])
		{
			
		}
		else {
			flag++;
			break;
		}
		Result[i] = DeOutput42[i];
	}
	for (size_t i = 0; i < 4; i++)
	{
		if (DeOutput22[i] == z1[i])
		{

		}
		else {
			flag++;
			break;
		}
		Result[i] = DeOutput42[i];
	}
	for (size_t i = 0; i < 4; i++)
	{
		if (DeOutput32[i] == z1[i])
		{

		}
		else {
			flag++;
			break;
		}
		Result[i] = DeOutput42[i];
	}
	for (size_t i = 0; i < 4; i++)
	{
		if (DeOutput42[i] == z1[i])
		{
			// printf("D[%d]: %02X - z1[%d]: %02X\n", i, DeOutput42[i], i, z1[i]);
		}
		else {
			flag++;
			break;
		}
		Result[i] = DeOutput42[i];
	}

	if (flag == 4)
	{
		// printf("\nWARNING !!! This Client is NOT valid for this round!\n");
		count++;
	}
	else {
		// printf("\nCONGRATULATIONS. This Client is VALID for this round.\n\n\n");
	}
}
/* ===============  4 验证 ===============  */
void verify(BIGNUM* alicePrivateKey, BIGNUM* alicePublicKey, 
	BIGNUM* bobPrivateKey, BIGNUM* bobPublicKey, 
	BIGNUM* carolPrivateKey, BIGNUM* carolPublicKey,
	BIGNUM* C, BIGNUM* C2, BIGNUM* C4, BIGNUM* C6)
{
	// decrypt PROOF, first carolPrivatekey, second bobPrivatekey
	// 第一次解密 Carol Private Key
	// BIGNUM* C2 = BN_new();
	BIGNUM* M1 = BN_new();
	rsatest_decrypt(M1, C6, carolPrivateKey, carolPublicKey);
	// printf("\nPalinText for PROOF Layer 2：\n%s\n", BN_bn2hex(M1));

	// 第二次解密 bob Private Key
	// BIGNUM* C = BN_new();
	BIGNUM* M2 = BN_new();
	rsatest_decrypt(M2, C4, carolPrivateKey, carolPublicKey);
	// printf("\nPalinText for PROOF Layer 1：\n%s\n", BN_bn2hex(M2));

	// decrypt PROOFS, first carolPrivatekey, second alicePrivatekey
	// 第一次解密 Carol Private Key
	// BIGNUM* C2 = BN_new();
	BIGNUM* M3 = BN_new();
	rsatest_decrypt(M3, C2, carolPrivateKey, carolPublicKey);
	// printf("\nPalinText for proofs Layer 2：\n%s\n", BN_bn2hex(M3));

	// 第二次解密 Alice Private Key
	// BIGNUM* C = BN_new();
	BIGNUM* M4 = BN_new();
	rsatest_decrypt(M4, C, carolPrivateKey, carolPublicKey);
	// printf("\nPalinText for proofs Layer 1：\n%s\n", BN_bn2hex(M4));

	// printf("\nZ from Client(ZC) --> Z from Server(ZS) --> Z1 from Verifier(ZV):\n");
	for (size_t i = 0; i < 4; i++)
	{
		// printf("ZC[%d]=%02X     -->     ZS[%d]=%02X     -->     ZV[%d]=%02X\n", i, z1[i], i, z1[i], i, z1[i]);
	}
	if (flag == 4)
	{
		// printf("\nWARNING !!! Transaction if NOT valid for this round!\n");

	}
	else {
		// printf("\nCONGRATULATIONS. Transaction SUCCESS for this round.\n\n\n");
	}
}



int main()
{
	for (size_t i = 0; i < 100; i++)
	{
		int a[10002];
		int i = 0;
		double run_time;
		LARGE_INTEGER time_start;	//开始时间
		LARGE_INTEGER time_over;	//结束时间
		double dqFreq;		//计时器频率
		LARGE_INTEGER f;	//计时器频率
		QueryPerformanceFrequency(&f);
		dqFreq = (double)f.QuadPart;
		QueryPerformanceCounter(&time_start);	//计时开始

		//printf("###############  Sub-Algorithm 1 - Gen() BEGIN ###############\n\n");
		GenPRF();
		GenGValues();
		BIGNUM* C = BN_new();
		BIGNUM* C2 = BN_new();
		BIGNUM* C4 = BN_new();
		BIGNUM* C6 = BN_new();
		// 公私钥对
		BIGNUM* e = BN_new();
		BN_hex2bn(&e, "10001");
		BIGNUM* carolPrivateKey = BN_new();
		BIGNUM* carolPublicKey = BN_new();
		BN_hex2bn(&carolPrivateKey, strprivate);
		BN_hex2bn(&carolPublicKey, strpublic);

		BIGNUM* alicePrivateKey = BN_new();
		BIGNUM* alicePublicKey = BN_new();
		BN_hex2bn(&alicePrivateKey, strprivate);
		BN_hex2bn(&alicePublicKey, strpublic);

		Proof1(alicePublicKey, carolPublicKey, e, C, C2);
		//printf("\n\n");
		//printf("###############  Sub-Algorithm 1 - Gen() Successfully END ! ###############\n\n\n");
		//printf("###############  Sub-Algorithm 2 - Compute() BEGIN ###############\n\n");
		computGC();
		BIGNUM* bobPrivateKey = BN_new();
		BIGNUM* bobPublicKey = BN_new();
		BN_hex2bn(&bobPrivateKey, strprivate);
		BN_hex2bn(&bobPublicKey, strpublic);
		proof2(bobPublicKey, carolPublicKey, e, C4, C6);
		//printf("###############  Sub-Algorithm 2 - Compute() Successfully END ! ###############\n\n\n");
		//printf("###############  Sub-Algorithm 3 - Lottery() BEGIN ###############\n\n");
		lottery();
		//printf("\n\n###############  Sub-Algorithm 3 - Lottery() Successfully END ! ###############\n\n\n");
		//printf("###############  Sub-Algorithm 4 - Verify() BEGIN ###############\n\n");
		verify(alicePrivateKey, alicePublicKey, bobPrivateKey, bobPublicKey, carolPrivateKey, carolPublicKey, C, C2, C4, C6);
		//printf("\n\n###############  Sub-Algorithm 4 - Verify() Successfully END ! ###############\n\n\n");



		//// 第一次解密 Carol Private Key
		//BIGNUM* M3 = BN_new();
		//rsatest_decrypt(M3, C2, carolPrivateKey, carolPublicKey);
		//printf("\nPalinText for Layer 2：\n%s\n", BN_bn2hex(M3));

		//// 第二次解密 Alice Private Key
		//BIGNUM* M4 = BN_new();
		//rsatest_decrypt(M4, C, carolPrivateKey, carolPublicKey);
		//printf("\nPalinText for Layer 1：\n%s\n", BN_bn2hex(M4));


		// printf("\n\n");


		QueryPerformanceCounter(&time_over);	//计时结束
		run_time = 1000000 * (time_over.QuadPart - time_start.QuadPart) / dqFreq;
		//乘以1000000把单位由秒化为微秒，精度为1000 000/（cpu主频）微秒
		printf("run_time：%fus\n", run_time);
	}
	printf("count = %d\n", count);
	



	//printf("\n\n");
	system("pause");
}

