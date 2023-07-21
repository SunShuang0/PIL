#pragma warning(disable:4996)
#include "rsatest.h"

int zhuanhuan(int a)//��ʮ������ת��Ϊʮ����
{
	if (a < 60)
	{
		a = a - '0';
	}
	if (a > 64)
	{
		a = a - 'A' + 10;
	}
	return a;
}

void rsatest_genkey(BIGNUM* d, BIGNUM* n, BIGNUM* e)
{
	BIGNUM* p = BN_new();    //������p
	BIGNUM* q = BN_new();  //������q
	//BIGNUM* n = BN_new();    //n = p*q public key
	BIGNUM* fn = BN_new();   //fn = (p-1)*(q-1) private key
	//BIGNUM* d = BN_new();    //d=e-1 mod (n)
	//BIGNUM* e = BN_new();   //����e��1<e<fn��gcd(fn, e)=1
	BIGNUM* r = BN_new();
	BN_CTX* ctx = BN_CTX_new();         //�����Ľṹ
	BIGNUM* one = BN_new();  //��one����Ϊ1
	BN_one(one);
	int length;
	char str[100] = "0";
	char* show;
	int bits = 512;     //512bits
	int i, j, t;
	int sum = 0;

	uint8_t ep[] = { 0x01,0x00,0x01 };

	BN_generate_prime(p, bits, NULL, NULL, NULL, NULL, NULL);       //����512bits�Ĵ�����p
	BN_generate_prime(q, bits, NULL, NULL, NULL, NULL, NULL);     //����512bits�Ĵ�����q

	BN_mul(n, p, q, ctx);            //n=p*q
	BN_sub(p, p, one);
	BN_sub(q, q, one);
	BN_mul(fn, p, q, ctx);           //fn=(p-1)*(q-1)
	do
	{
		//BN_rand_range(e, fn); //������0 < e < fn�������
		BN_bin2bn(ep, 3, e);
		BN_gcd(r, e, fn, ctx); //r = e, fn���Լ��
	} while (!BN_is_one(r)); //�ж�r�Ƿ����1
	BN_mod_inverse(d, e, fn, ctx);    //ģ������

	// printf("\npublic key��%s\n", BN_bn2hex(n));
	// printf("\nprivate key��%s\n", BN_bn2hex(fn));

}

// nΪ��Կ
void rsatest_ecrypt(BIGNUM* C, BIGNUM* M, BIGNUM* e, BIGNUM* n)
{
	BN_CTX* ctx = BN_CTX_new();

	//��Կ���� C = M^e mod n
	BN_mod_exp_simple(C, M, e, n, ctx);

	// uint8_t* show;
	// show = BN_bn2hex(C);		//������ת��Ϊʮ������
	// printf("����:%s\n", show);
}
// dΪ��Կ
void rsatest_decrypt(BIGNUM* M, BIGNUM* C, BIGNUM* d, BIGNUM* n)
{
	BN_CTX* ctx = BN_CTX_new();

	//˽Կ���� M = C^d mod n��
	BN_mod_exp_simple(M, C, d, n, ctx);

	//uint8_t* show = (uint8_t*)malloc(256);
	//show = BN_bn2hex(M);
	//printf("\n���ܺ������:%s", show);		//�����ܺ������ת��Ϊʮ������
}

void rsatest()
{

	uint8_t plaintext[] = { 0X1C, 0X5B, 0X5A, 0X6B, 0XDA, 0X5F, 0XC6, 0X0D,
						0X55, 0X02, 0XFA, 0XD7, 0X09, 0X55, 0X49, 0XBC,
						0X55, 0X42, 0X50, 0X78, 0X55, 0X42, 0X50, 0X78 };
	//uint8_t* ciphertext[128] = { 0x00 };

	//uint8_t ep[] = {0x01,0x00,0x01};
	BIGNUM* alicePrivateKey = BN_new();
	BIGNUM* alicePublicKey = BN_new();

	BIGNUM* M = BN_new();
	BIGNUM* M2 = BN_new();
	BIGNUM* C = BN_new();	// ���ܽ��
	BIGNUM* e = BN_new();

	BN_bin2bn(plaintext, 24, M);

	rsatest_genkey(alicePrivateKey, alicePublicKey, e);

	//printf("\nalicePublicKey key��%s\n", BN_bn2hex(alicePublicKey));
	//printf("\nalicePrivateKey key��%s\n", BN_bn2hex(alicePrivateKey));
	//printf("\ne��%s\n", BN_bn2hex(e));


	rsatest_ecrypt(C, M, e, alicePublicKey);
	//printf("\nC��%s\n", BN_bn2hex(C));

	//BIGNUM* d = BN_new();
	rsatest_decrypt(M2, C, alicePrivateKey, alicePublicKey);
	//printf("\nM2��%s\n", BN_bn2hex(M2));





	////�ͷŽṹ
	//BN_CTX_free(ctx);
	//BN_free(parameter_p);
	//BN_free(parameter_q);
	//BN_free(pq);
	//BN_free(fn);
	//BN_free(testPrivateKey);
	//BN_free(testPublicKey);
	//BN_free(r);
	//BN_free(PlainText);
	//BN_free(CipherText);
}