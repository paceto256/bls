#include <bls/bls384_256.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

void makePair(blsSecretKey *sec, blsPublicKey *pub) {
    // init SecretKey sec by random number
    blsSecretKeySetByCSPRNG(sec);
    // get PublicKey pub from SecretKey sec
    blsGetPublicKey(pub, sec);
}

void dumpSig2(blsSignature *sig)
{
	unsigned char buf[1024];
	size_t n = blsSignatureSerialize(buf, sizeof(buf), sig);
	for (size_t i = n; i > 0; i--) printf("%02x", buf[i-1]);
}

void dumpSig(blsSignature *sig)
{
	unsigned char buf[1024];
	size_t n = blsSignatureGetHexStr(buf, sizeof(buf), sig);
    printf("%s", buf);
}

void dumpSec(blsSecretKey *sec)
{
	unsigned char buf[1024];
	size_t n = blsSecretKeyGetHexStr(buf, sizeof(buf), sec);
    printf("%s", buf);
}

void dumpSec2(blsSecretKey *sec)
{
	unsigned char buf[1024];
	size_t n = blsSecretKeySerialize(buf, sizeof(buf), sec);
	for (size_t i = n; i > 0; i--) printf("%02x", buf[i-1]);
}

void dumpPub2(blsPublicKey *pub)
{
	unsigned char buf[1024];
	size_t n = blsPublicKeySerialize(buf, sizeof(buf), pub);
	for (size_t i = n/2; i > 0; i--) {
	    printf("%02x", buf[i-1]);
	}
}

void dumpPub(blsPublicKey *pub)
{
	unsigned char buf[128];
	size_t n = blsPublicKeyGetHexStr(buf, sizeof(buf), pub);
    printf("%s", buf);
}

void pub2hex(blsPublicKey *pub, char *hex)
{
	unsigned char buf[96];
	size_t n = blsPublicKeySerialize(buf, 96, pub);

    for (size_t i = n; i > 0; i--) {
        char row[4];
        sprintf(row, "%02x", buf[i-1]);
        strcat(hex, row);
    }
}


void sec2hex(blsSecretKey *sec, char *hex)
{
	unsigned char buf[64];

	size_t n = blsSecretKeySerialize(buf, 64, sec);

	for (size_t i = n; i > 0; i--) {
        char row[4];
        sprintf(row, "%02x", buf[i-1]);
        strcat(hex, row);
	}
}

void sig2hex(blsSignature *sig, char *hex)
{
	unsigned char buf[256];

	size_t n = blsSignatureSerialize(buf, 256, sig);

	for (size_t i = n; i > 0; i--) {
        char row[4];
        sprintf(row, "%02x", buf[i-1]);
        strcat(hex, row);
	}
}


/*
 ********************************
 *
 * Usage: bls_api generatePair
 *
 ********************************
*/
void generatePair()
{
	blsSecretKey sec;
	blsPublicKey pub;

	makePair(&sec, &pub);

    char privateKey[1024] = "";
    char publicKey[1024] = "";

	sec2hex(&sec, privateKey);
	pub2hex(&pub, publicKey);

    printf("{"
        "\"privateKey\":\"%s\","
        "\"publicKey\":\"%s\""
    "}", privateKey, publicKey);
}

/*
 ******************************************
 * Sign
 * Usage: bls_api sign {msg} {privateKey}
 *
 ******************************************
*/
void sign(char *msg, char *privateKey)
{
	blsSecretKey sec;
    blsSecretKeySetHexStr(&sec, privateKey, 64);

    blsSignature sig;
    blsSign(&sig, &sec, msg, strlen(msg));

    char signature[256] = "";

//dumpSig2(&sig);
//printf("\n");
//dumpSig(&sig);
//printf("\n");
//
//    //sig2hex(&sig, signature);
//
//printf("\n");
//
//
//    printf("{"
//        "\"signature\":\"%s\","
//        "\"msg\":\"%s\""
//    "}",signature, msg);
}


/*
 ********************************************************
 *
 * Usage: bls_api verify {msg} {signature} {publicKey}
 *
 ********************************************************
*/
void verify(char *msg, char *signature, char *publicKey)
{
	blsPublicKey pub;
	size_t nnn;
    nnn = blsPublicKeySetHexStr(&pub, publicKey, strlen(publicKey));
    //nnn = blsPublicKeyDeserialize(&pub, publicKey, strlen(publicKey));

dumpPub(&pub);

}

void test () {
    char p[] = "13fcc546da6b6eae061805b22531e5d4636fc3ee6642af1bb4316c3caa21fecee34e3d2f8d72824a6398f5bda9f4f4c5";
    char s[] = "3bc875680b14caa410fd9f45341123bfa638cbef3d1803f7712be72d6cc695fc";

	blsSecretKey sec;
	blsPublicKey pub;
	blsSignature sig;

    makePair(&sec, &pub);

    size_t n1;
    size_t n2;

	n1 = blsPublicKeySetHexStr(&pub, p, strlen(p));
	n2 = blsSecretKeySetHexStr(&sec, s, strlen(s));
	printf("n1=%d\n", n1);
	printf("n2=%d\n", n2);

	const char *msg = "This is a pen";
	const size_t msgSize = strlen(msg);

	dumpPub(&pub);

    printf("\n");
    dumpPub2(&pub);
    printf("\n");

	dumpSec(&sec);
	printf("\n");
	dumpSec2(&sec);

	blsSecretKeySetByCSPRNG(&sec);

	blsGetPublicKey(&pub, &sec);

	blsSign(&sig, &sec, msg, msgSize);

	printf("\n%d", blsVerify(&sig, &pub, msg, msgSize));
}

// make && make install && clear && time ../bin/minsample getPair
int main(int argc, char *argv[])
{
	int r = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (r != 0) {
		printf("err blsInit %d\n", r);
		return 1;
	}

	if (!strcmp("generatePair",argv[1])) {
	    generatePair();
	} else if (!strcmp("sign",argv[1])) {
	    for (int i = 0; i < 1000; i++) {
	        sign(argv[2], argv[3]);
	    }

	} else if (!strcmp("verify", argv[1])) {
	    verify(argv[2], argv[3], argv[4]);
	}  else if (!strcmp("test", argv[1])) {
	    test(argv[2], argv[3]);
	}


	return 0;
}
