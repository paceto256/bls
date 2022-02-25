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

void dumpPub(blsPublicKey *pub)
{
	unsigned char buf[256];
	size_t n = blsPublicKeySerialize(buf, sizeof(buf), pub);
	for (size_t i = n; i > 0; i--) {
		printf("%02x", buf[i-1]);
	}
}

void pub2hex(blsPublicKey *pub, char *hex)
{
	unsigned char buf[256];
	size_t n = blsPublicKeySerialize(buf, 256, pub);

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

/** Usage: bls_api generatePair */
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

//void str2sec(blsSecretKey *sec, const void *buf, mclSize bufSize)
//{
//    blsSecretKeyDeserialize(blsSecretKey *sec, const void *buf, mclSize bufSize);
//}

//mclSize blsSecretKeyDeserialize(blsSecretKey *sec, const void *buf, mclSize bufSize);
//mclSize blsPublicKeyDeserialize(blsPublicKey *pub, const void *buf, mclSize bufSize);
//mclSize blsSignatureDeserialize(blsSignature *sig, const void *buf, mclSize bufSize);

// {"privateKey":"56c002ce9ce7f7ec6b4859cc9550d4f4f76dcb15073b6083be1b236fe7896c5e","publicKey":"146fbd798abeeb7413e6ecc055dc8182bd2a10f4863b466f91aa2ef6618c4f7376ae81bfcf59666e7bc5da9a0a106256035c991a1c31510b697a6956ed8e1c8482491711ae5c5f82fdc8eec380d7580724a49de0f797b2e263fa37856914c57b"}
// sign 9933158d568e1701d2d3c044570b38e5362675783f8a73a80b53a4ca0a3e39fdd13ef6ae238620f95fb09ce7f34fee57
// Usage: bls_api sign {message} {privateKey}
void sign(char *msg, char *privateKey)
{
	blsSecretKey sec;
    blsSecretKeySetHexStr(&sec, privateKey, 64);

    blsSignature sig;
    blsSign(&sig, &sec, msg, strlen(msg));

    char signature[256] = "";

    sig2hex(&sig, signature);

    printf("{"
        "\"signature\":\"%s\","
        "\"msg\":\"%s\""
    "}",signature, msg);
}

void verify(char *msg, char *signature, char *publicKey)
{
//	blsPublicKey pub;
//  blsPublicKeySetHexStr(&pub, publicKey, 192);

    const char hexSig[] = "9933158d568e1701d2d3c044570b38e5362675783f8a73a80b53a4ca0a3e39fdd13ef6ae238620f95fb09ce7f34fee57";
    blsSignature sig;
    blsSignatureSetHexStr(&sig, hexSig, strlen(hexSig));

    unsigned char buf1[1024];
    size_t n1 = blsSignatureSerialize(buf1, sizeof(buf1), &sig);
    for (size_t i = n1; i > 0; i--) printf("%02x", buf1[i-1]);

    printf("\n");

    unsigned char buf[1024];
    size_t n = blsSignatureGetHexStr(buf, sizeof(buf), &sig);
    printf("%s", buf);

printf("\n");

//
//    char s[1024] = "";
//    char p[1024] = "";
//    sig2hex(&sig, s);
//    pub2hex(&pub, p);
//
//    printf("{"
//        "\"s\":\"%s\","
//        "\"p\":\"%s\","
//        "\"msg\":\"%s\""
//    "}",s, p, msg);

    // printf("verify correct message %d \"%s\"\n", blsVerify(&sig, &pub, msg, strlen(msg)), msg);

//	printf("verify correct message %d \"%s\"\n", blsVerify(&sig, &pub, msg, msgSize), msg);
//	printf("verify wrong message %d\n", blsVerify(&sig, &pub, "xyz", msgSize));

//    printf("{"
//        "\"blsVerify\":\"%s\""
//    "}", blsVerify(&sig, &pub, msg, strlen(msg)));
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
	    sign(argv[2], argv[3]);
	} else if (!strcmp("verify", argv[1])) {
	    verify(argv[2], argv[3], argv[4]);
	}

	return 0;
}



//void simpleSample()
//{
//	blsSecretKey sec;
//	blsPublicKey pub;
//
//
//	blsSignature sig;
//	const char *msg = "Hello World!";
//	size_t msgSize = 12;
//
//	blsSign(&sig, &sec, msg, msgSize);
//
//	printf("verify correct message %d \"%s\"\n", blsVerify(&sig, &pub, msg, msgSize), msg);
//	printf("verify wrong message %d\n", blsVerify(&sig, &pub, "xyz", msgSize));
//}

//void k_of_nSample()
//{
//#define N 5 // you can increase
//#define K 3 // fixed
//	blsPublicKey mpk;
//	blsId ids[N];
//	blsSecretKey secs[N];
//	blsPublicKey pubs[N];
//	blsSignature sigs[N];
//
//	const char *msg = "abc";
//	const size_t msgSize = strlen(msg);
//
//	// All ids must be non-zero and different from each other.
//	for (int i = 0; i < N; i++) {
//		blsIdSetInt(&ids[i], i + 1);
//	}
//
//	/*
//		A trusted third party distributes N secret keys.
//		If you want to avoid it, then see DKG (distributed key generation),
//		which is out of the scope of this library.
//	*/
//	{
//		blsSecretKey msk[K];
//		for (int i = 0; i < K; i++) {
//			blsSecretKeySetByCSPRNG(&msk[i]);
//		}
//		// share secret key
//		for (int i = 0; i < N; i++) {
//			blsSecretKeyShare(&secs[i], msk, K, &ids[i]);
//		}
//
//		// get master public key
//		blsGetPublicKey(&mpk, &msk[0]);
//
//		// each user gets their own public key
//		for (int i = 0; i < N; i++) {
//			blsGetPublicKey(&pubs[i], &secs[i]);
//		}
//	}
//
//	// each user signs the message
//	for (int i = 0; i < N; i++) {
//		blsSign(&sigs[i], &secs[i], msg, msgSize);
//	}
//
//	// The master signature can be recovered from any K subset of N sigs.
//	{
//		assert(K == 3);
//		blsSignature subSigs[K];
//		blsId subIds[K];
//		for (int i = 0; i < N; i++) {
//			subSigs[0] = sigs[i];
//			subIds[0] = ids[i];
//			for (int j = i + 1; j < N; j++) {
//				subSigs[1] = sigs[j];
//				subIds[1] = ids[j];
//				for (int k = j + 1; k < N; k++) {
//					subSigs[2] = sigs[k];
//					subIds[2] = ids[k];
//					// recover sig from subSigs[K] and subIds[K]
//					blsSignature sig;
//					blsSignatureRecover(&sig, subSigs, subIds, K);
//					if (!blsVerify(&sig, &mpk, msg, msgSize)) {
//						printf("ERR can't recover i=%d, j=%d, k=%d\n", i, j, k);
//						return;
//					}
//				}
//			}
//		}
//		puts("recover test1 is ok");
//	}
//
//	// any K-1 of N sigs can't recover
//	{
//		assert(K == 3);
//		blsSignature subSigs[K - 1];
//		blsId subIds[K - 1];
//		for (int i = 0; i < N; i++) {
//			subSigs[0] = sigs[i];
//			subIds[0] = ids[i];
//			for (int j = i + 1; j < N; j++) {
//				subSigs[1] = sigs[j];
//				subIds[1] = ids[j];
//				// can't recover sig from subSigs[K-1] and subIds[K-1]
//				blsSignature sig;
//				blsSignatureRecover(&sig, subSigs, subIds, K - 1);
//				if (blsVerify(&sig, &mpk, msg, msgSize)) {
//					printf("ERR verify must always fail. i=%d, j=%d\n", i, j);
//					return;
//				}
//			}
//		}
//		puts("recover test2 is ok");
//	}
//#undef K
//#undef N
//}