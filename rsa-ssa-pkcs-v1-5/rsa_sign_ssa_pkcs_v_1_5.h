#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/rsa.h>

/**
 * @brief Generate RSA signature according to the SSA (Signature Scheme Algorithm) PKCS v1.5
 *
 * @param[in] RsaKey RSA key
 * @param[in] msg The message to be signed
 * @param[in] msgLen The message's length
 * @param[out] signature Buffer that will hold the generated signature
 * @param[in] signatureLen The length of the signature buffer
 * @param[in] hashAlg The hash algorithm to be used (e.g WC_HASH_TYPE_SHA256, WC_HASH_TYPE_SHA384, WC_HASH_TYPE_SHA512)
 *
 * @return The signature size in case of success and a negative value in case of error
 */
int rsa_sign_ssa_pkcs_v_1_5(RsaKey * rsaKey, const byte * msg, unsigned int msgLen,
  byte * signature, unsigned int signatureLen, enum wc_HashType hashAlg);
