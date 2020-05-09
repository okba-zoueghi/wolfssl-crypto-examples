#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/dsa.h>

/* (p, q) = (1024, 160)*/
#define DSA_MODULUS_SIZE_1024 1024

/* (p, q) = (2048, 256)*/
#define DSA_MODULUS_SIZE_2048 2048

/* (p, q) = (3072, 256)*/
#define DSA_MODULUS_SIZE_3072 3072

/* Signature size when using moduls size equal to 1024*/
#define DSA_SIGNATURE_SIZE_WITH_MODULUS_1024 (160/4)

/* Signature size when using moduls size equal to 2048*/
#define DSA_SIGNATURE_SIZE_WITH_MODULUS_2048 (256/4)

/* Signature size when using moduls size equal to 3072*/
#define DSA_SIGNATURE_SIZE_WITH_MODULUS_3072 (256/4)

/**
 * @brief Sign according to the Digital Signature Algorithm (DSA)
 *
 * @param[in] dsaKey DSA key
 * @param[in] msg The message to be signed
 * @param[in] msgLen The message's length
 * @param[out] signature Buffer that will hold the generated signature
 * @param[in] hashAlg The hash algorithm to be used (e.g WC_HASH_TYPE_SHA256, WC_HASH_TYPE_SHA384, WC_HASH_TYPE_SHA512)
 *
 * @return The signature size in case of success and a negative value in case of error
 */
int dsa_sign(DsaKey * dsaKey, const byte * msg, unsigned int msgLen,
  byte * signature, enum wc_HashType hashAlg);

/**
 * @brief Verify according to the Digital Signature Algorithm (DSA)
 *
 * @param[in] dsaKey DSA key
 * @param[in] msg The message of which the signature is provided
 * @param[in] msgLen The message's length
 * @param[in] signature The message's signature to be verified
 * @param[out] verificationResult will be set 1 if the signature verification succeeds and set to 0 if it fails
 * @param[in] hashAlg The hash algorithm to be used (e.g WC_HASH_TYPE_SHA256, WC_HASH_TYPE_SHA384, WC_HASH_TYPE_SHA512)
 *
 * @return 0 if the signature verification is processed successfully and another value otherwise
 *         0 doesn't mean that the signature verification is successful, it only means the verification is processed
 */
int dsa_verify(DsaKey * dsaKey, const byte * msg, unsigned int msgLen,
  byte * signature, int * verificationResult, enum wc_HashType hashAlg);
