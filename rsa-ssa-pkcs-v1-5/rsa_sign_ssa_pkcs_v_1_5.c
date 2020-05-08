#include <stdio.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "rsa_sign_ssa_pkcs_v_1_5.h"

/* Maximum bound on digest algorithm encoding around digest */
#define MAX_ENC_ALG_SZ      32

/* Signature Generation Steps - Signature Scheme Algorithm RSA-SSA-PKCS-V-1_5
 * 1- Compute the hash of the message, the hash function could be sha256, sha384, etc...
 * The result of the hash is H(m)
 * 2- Construct T = Hash_Alg_Id | H(m)
 * 3- Construct the Encoded Message EM = 0x00 | 0x01 | PS | 0x00 | T
 * with PS = 0xFF | ... | 0xFF a padding to have size(EM) equal to size(RSA modulus)
 * 4- Get the integer representation of the encoded message m = OS2IP(EM)
 * 5- Compute the signature s = m^d mod(n)
 * 6- Get the string representation of the signature S = I2OSP(s,n)
 */
int rsa_sign_ssa_pkcs_v_1_5(RsaKey * rsaKey, const byte * msg, unsigned int msgLen,
  byte * signature, unsigned int signatureLen, enum wc_HashType hashAlg)
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

  /* Construct T*/
  byte * T = (byte *)malloc(digestSize + MAX_ENC_ALG_SZ);
  ret = wc_EncodeSignature(T, digest, digestSize, wc_HashGetOID(hashAlg));

  if(ret < 0)
  {
    fprintf(stderr, "Failed to construct T\n");
    return ret;
  }

  int Tsize = ret;

  /* Construct EM ans sign */
  WC_RNG rng;
  ret = wc_InitRng(&rng);

  if(ret != 0)
  {
    fprintf(stderr, "Failed to initialize the rng\n");
    return ret;
  }

  ret = wc_RsaSSL_Sign(T, Tsize, signature, signatureLen, rsaKey, &rng);

  free(digest);
  free(T);
  wc_FreeRng(&rng);

  return ret;
};
