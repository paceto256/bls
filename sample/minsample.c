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

void secretToString(blsSecretKey *sec, char *string)
{
    unsigned char buf[128];
    size_t n = blsSecretKeySerialize(buf, sizeof(buf), &sec);
    n = blsSecretKeySerialize(buf, sizeof(buf), &sec);
	for (size_t i = 0; i < n; i++) sprintf(string + strlen(string) , "%02x", buf[i]);
}

void publicKeyToString(blsPublicKey *pub, char *string)
{
    unsigned char buf[128];
    size_t n = blsPublicKeySerialize(buf, sizeof(buf), &pub);
    n = blsPublicKeySerialize(buf, sizeof(buf), &pub);
    for (size_t i = 0; i < n; i++) sprintf(string + strlen(string) , "%02x", buf[i]);
}

/**
*
*/
void generatePair()
{
	blsSecretKey sec;
	blsPublicKey pub;

    setPair(&sec, &pub);

    char privateKey[128];
    char publicKey[128];

    secretToString(&sec, privateKey);
    publicKeyToString(&pub, publicKey);

    printf("{\"privateKey\":\"%s\", \"publicKey\":\"%s\"}", privateKey, publicKey);
}

void sign()
{
	blsSecretKey sec;
	blsPublicKey pub;

    setPair(&sec, &pub);

    char privateKey[128];
    char publicKey[128];

    secretToString(&sec, privateKey);
    publicKeyToString(&pub, publicKey);

    printf("{\"privateKey\":\"%s\", \"publicKey\":\"%s\"}", privateKey, publicKey);
}


//      printf("%02x", buf[i]);
//	    char buffer[1];
//	    sprintf(buffer, "%02x", buf[i]);
//	    strcat(string,buffer);




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

const static struct {
  const char *name;
  void (*func)(void);
} function_map [] = {
  { "generatePair", generatePair },
};

int call_function(const char *name)
{
  int i;

  for (i = 0; i < (sizeof(function_map) / sizeof(function_map[0])); i++) {
    if (!strcmp(function_map[i].name, name) && function_map[i].func) {
      function_map[i].func();
      return 0;
    }
  }

  return -1;
}

// make && make install && clear && time ../bin/minsample getPair
int main(int argc, char *argv[])
{
	int r = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
	if (r != 0) {
		printf("err blsInit %d\n", r);
		return 1;
	}

	call_function(argv[1]);
	return 0;
}