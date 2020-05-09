#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "dsa.h"

int dsa_sign(DsaKey * dsaKey, const byte * msg, unsigned int msgLen,
  byte * signature, enum wc_HashType hashAlg)
{
  int ret = 0;

  ret = wc_HashGetDigestSize(hashAlg);

  if (ret <= 0)
  {
    fprintf(stderr, "Hash algorithm unknown or not supported\n");
    return ret;
  }

  int digestSize = ret;

  byte * digest = (byte*)malloc(digestSize);

  if (!digest)
  {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  /* Compute H(m)*/
  ret = wc_Hash(hashAlg, msg, msgLen, digest, digestSize);

  if(ret != 0)
  {
    fprintf(stderr, "Failed to compute the hash\n");
    return ret;
  }

  WC_RNG rng;
  ret = wc_InitRng(&rng);

  if(ret != 0)
  {
    fprintf(stderr, "Failed to initialize the rng\n");
    return ret;
  }

  ret = wc_DsaSign(digest, signature, dsaKey, &rng);

  free(digest);
  wc_FreeRng(&rng);

  return ret;
}

int dsa_verify(DsaKey * dsaKey, const byte * msg, unsigned int msgLen,
  byte * signature, int * verificationResult, enum wc_HashType hashAlg)
{
  int ret = 0;

  ret = wc_HashGetDigestSize(hashAlg);

  if (ret <= 0)
  {
    fprintf(stderr, "Hash algorithm unknown or not supported\n");
    return ret;
  }

  int digestSize = ret;

  byte * digest = (byte*)malloc(digestSize);

  if (!digest)
  {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  /* Compute H(m)*/
  ret = wc_Hash(hashAlg, msg, msgLen, digest, digestSize);

  if(ret != 0)
  {
    fprintf(stderr, "Failed to compute the hash\n");
    return ret;
  }

  ret = wc_DsaVerify(digest, signature, dsaKey, verificationResult);

  free(digest);

  return ret;
}
