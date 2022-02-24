#include <bls/bls384_256.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

void setPair(blsSecretKey *sec, blsPublicKey *pub) {
    // init SecretKey sec by random number
    blsSecretKeySetByCSPRNG(sec);
    // get PublicKey pub from SecretKey sec
    blsGetPublicKey(pub, sec);
}

void dumpSec(blsSecretKey *sec)
{
	unsigned char buf[64];
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

// Usage: bls_api generatePair
void generatePair()
{
	blsSecretKey sec;
	blsPublicKey pub;

	setPair(&sec, &pub);

    char privateKey[128] = "";
    char publicKey[256] = "";

	sec2hex(&sec, privateKey);
	pub2hex(&pub, publicKey);

    printf("{"
        "\"privateKey\":\"%s\","
        "\"publicKey\":\"%s\""
    "}",privateKey, publicKey);
}

//void str2sec(blsSecretKey *sec, const void *buf, mclSize bufSize)
//{
//    blsSecretKeyDeserialize(blsSecretKey *sec, const void *buf, mclSize bufSize);
//}


//mclSize blsSecretKeyDeserialize(blsSecretKey *sec, const void *buf, mclSize bufSize);
//mclSize blsPublicKeyDeserialize(blsPublicKey *pub, const void *buf, mclSize bufSize);
//mclSize blsSignatureDeserialize(blsSignature *sig, const void *buf, mclSize bufSize);


// Usage: bls_api sign {message} {privateKey}
void sign(char *msg, char *privateKey)
{
	blsSecretKey sec;
    blsSecretKeySetHexStr(&sec, privateKey, sizeof(privateKey));

//    // unsigned char buf[128];
//    size_t n = blsPublicKeySerialize(buf, sizeof(buf), &pub);
//    for (size_t i = 0; i < n; i++) sprintf(string + strlen(string) , "%02x", buf[i]);

//    blsSecretKeyDeserialize(&sec, privateKey, sizeof(privateKey));
//
//	char test[128];
//	sec2hex(&sec, test);

	printf("{"
        "\"test\":\"%s\""
    "}",privateKey);

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
//    setPair(&sec, &pub);
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