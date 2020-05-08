#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#include "rsa_ssa_pkcs_v_1_5.h"

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

  WC_RNG rng;
  ret = wc_InitRng(&rng);

  if(ret != 0)
  {
    fprintf(stderr, "Failed to initialize the rng\n");
    return ret;
  }

  /* Construct EM and sign */
  ret = wc_RsaSSL_Sign(T, Tsize, signature, signatureLen, rsaKey, &rng);

  free(digest);
  free(T);
  wc_FreeRng(&rng);

  return ret;
};

/* Signature Generation Steps - Signature Scheme Algorithm RSA-SSA-PKCS-V-1_5
 * 1- Compute the hash of the message, the hash function could be sha256, sha384, etc...
 * The result of the hash is H(m)
 * 2- Construct T1 = Hash_Alg_Id | H(m)
 * 3- Decrypt the signature to get m the integer representation of EM (m = s^e mod(n))
 * 4- Get EM the string representation of the encoded message  EM = I2OSP(m)
 * 5- Decode EM to get T2
 * 6- Return true if T2 and T1 are equal
 */
int rsa_verify_ssa_pkcs_v_1_5(RsaKey * rsaKey, const byte * msg, unsigned int msgLen,
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

  /* Construct T1*/
  byte * T1 = (byte *)malloc(digestSize + MAX_ENC_ALG_SZ);
  ret = wc_EncodeSignature(T1, digest, digestSize, wc_HashGetOID(hashAlg));

  if(ret < 0)
  {
    fprintf(stderr, "Failed to construct T\n");
    return ret;
  }

  int T1size = ret;

  WC_RNG rng;
  ret = wc_InitRng(&rng);

  if(ret != 0)
  {
    fprintf(stderr, "Failed to initialize the rng\n");
    return ret;
  }

  /* Decrypt the signature to get EM then decode EM to get T*/
  byte * T2;
  ret = wc_RsaSSL_VerifyInline(signature, signatureLen, &T2, rsaKey);

  if(ret < 0)
  {
    fprintf(stderr, "Failed to decrypt and decode the signature\n");
    return ret;
  }

  int T2size = ret;

  if(T1size != T2size)
  {
    fprintf(stderr, "Failed, T1 and T2 have different sizes\n");
    return -1;
  }

  ret = memcmp(T1, T2, T1size);

  free(digest);
  free(T1);
  wc_FreeRng(&rng);

  return ret;
};
