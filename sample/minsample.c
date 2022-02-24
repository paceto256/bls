#include <bls/bls384_256.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

void initPair(blsSecretKey *sec, blsPublicKey *pub) {
    // init SecretKey sec by random number
    blsSecretKeySetByCSPRNG(sec);
    // get PublicKey pub from SecretKey sec
    blsGetPublicKey(pub, sec);
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
	for (size_t i = 0; i < n; i++) {
		printf("%02x", buf[i]);
	}
}

void dumpPub(blsPublicKey *pub)
{
	unsigned char buf[256];
	size_t n = blsPublicKeySerialize(buf, sizeof(buf), pub);
	for (size_t i = 0; i < n; i++) {
		printf("%02x", buf[i]);
	}
}

void pub2hex(blsPublicKey *pub, char *hex)
{
	unsigned char buf[256];
	size_t n = blsPublicKeySerialize(buf, 256, pub);

	for (size_t i = 0; i < n; i++) {
        char row[4];
        sprintf(row, "%02x", buf[i]);
        strcat(hex, row);
	}
}


void sec2hex(blsSecretKey *sec, char *hex)
{
	unsigned char buf[64];

	size_t n = blsSecretKeySerialize(buf, 128, sec);

	for (size_t i = 0; i < n; i++) {
        char row[4];
        sprintf(row, "%02x", buf[i]);
        strcat(hex, row);
	}
}

/** Usage: bls_api generatePair */
void generatePair()
{
	blsSecretKey sec;
	blsPublicKey pub;

	initPair(&sec, &pub);

    char privateKey[1024] = "";
    char publicKey[1024] = "";

    // blsSecretKeyGetHexStr(privateKey, 1024, &sec);
    // blsPublicKeySerialize(publicKey, 1024, &pub);

	sec2hex(&sec, privateKey);
	pub2hex(&pub, publicKey);

	dumpSec(&sec);
	printf("\n");
	dumpSec2(&sec);

//    printf("{"
//        "\"privateKey\":\"%s\","
//        "\"publicKey\":\"%s\""
//    "}", privateKey, publicKey);

//    printf("{"
//        "\"n\":\"%d\","
//    "}", n);

}

//void str2sec(blsSecretKey *sec, const void *buf, mclSize bufSize)
//{
//    blsSecretKeyDeserialize(blsSecretKey *sec, const void *buf, mclSize bufSize);
//}

//mclSize blsSecretKeyDeserialize(blsSecretKey *sec, const void *buf, mclSize bufSize);
//mclSize blsPublicKeyDeserialize(blsPublicKey *pub, const void *buf, mclSize bufSize);
//mclSize blsSignatureDeserialize(blsSignature *sig, const void *buf, mclSize bufSize);

// {"privateKey":"c930dbe93a1abd8bb25e38e89c807f49aca5f055c05b58bcc464630de3922a47","publicKey":"13e40a4b0207e760d3f8fe7fd9e7c712fdd59ce2e9cd3667e44d1245076c4398c6e6c7a4fb49f9a5f4b3badffb5a7d0b53255755ffdd67719f2c844bf0831962df2d7b39f5afdc30899eca45f876200e8b5b1231b99d4727dd588e2581fe0992"}
// {"privateKey":"2081e0e8c8c29adbc9bb35fc7f5b67f8cd1560cb21141b24655ac6748ba34f08","publicKey":"eeda78eb74a12de633242881958efa024fc94b9f69b81f28840d4cfb60579baa54980e46195a4a57a158f3bfee5b0705b06130d22b0f615191af09cd5fcbeef680f84e36b4bfda2bf695f2540741ac657ddf8dbcb3491bc51dd181f97eea4f0f"}


// Usage: bls_api sign {message} {privateKey}
void sign(char *msg, char *privateKey)
{
	blsSecretKey sec;
    blsSecretKeySetHexStr(&sec, privateKey, 64);
    printf("%s\n|%d|\n", privateKey, 1);
    dumpSec(&sec);

//    printf("{"
//        "\"asd\":\"%s\","
////        "\"buf\":\"%s\","
//    "}",asd);

//    // unsigned char buf[128];
//    size_t n = blsPublicKeySerialize(buf, sizeof(buf), &pub);
//    for (size_t i = 0; i < n; i++) sprintf(string + strlen(string) , "%02x", buf[i]);

//    blsSecretKeyDeserialize(&sec, privateKey, sizeof(privateKey));
//
//	char test[128];
//	sec2hex(&sec, test);

    // blsSecretKeyDeserialize(blsSecretKey *sec, const void *buf, mclSize bufSize);
	// str2sec(&sec, privateKey, strlen(privateKey));
    // printf("%s %s", msg, privateKey);

//    blsSignature sig;
//    blsSign(&sig, &sec, msg, strlen(msg));

//	printf("verify correct message %d \"%s\"\n", blsVerify(&sig, &pub, msg, msgSize), msg);
//	printf("verify wrong message %d\n", blsVerify(&sig, &pub, "xyz", msgSize));

//    printf("{"
//        "\"privateKey\":\"%s\","
//        "\"publicKey\":\"%s\""
//    "}",privateKey, publicKey);

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