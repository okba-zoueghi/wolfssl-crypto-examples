#include "dsa.h"

/* Print out the buffer in C code.
 *
 * name  [in]  Name of the variable.
 * data  [in]  Data to print out.
 * len   [in]  Length of the data.
 */
void print_buffer(char* name, unsigned char* data, word32 len)
{
    word32 i;

    printf("unsigned char %s[] = {\n", name);
    for (i = 0; i < len; i++) {
        if ((i % 8) == 0)
            printf("   ");
        printf(" 0x%02x,", data[i]);
        if ((i % 8) == 7)
            printf("\n");
    }
    if ((i % 8) != 0)
        printf("\n");
    printf("};\n");

}

int main(int argc, char* argv[])
{
  int ret;

  DsaKey dsaKey;

  byte signature[DSA_SIGNATURE_SIZE_WITH_MODULUS_1024];

  byte * msg;
  int msgLen;

  /* Get the message to sign from the command line */
  if (argc != 2)
  {
    fprintf(stderr, "Message to sign required\n");
    ret = -1;
  }
  else
  {
    msg = (unsigned char*)argv[1];
    msgLen = strlen(argv[1]);
  }

  WC_RNG rng;
  ret = wc_InitRng(&rng);

  if(ret != 0)
  {
    fprintf(stderr, "Failed to initialize the rng\n");
    return ret;
  }

  ret = wc_InitDsaKey(&dsaKey);

  if(ret != 0)
  {
    fprintf(stderr, "Failed to initialize the DSA key\n");
    return ret;
  }

  ret = wc_MakeDsaParameters(&rng, DSA_MODULUS_SIZE_1024, &dsaKey);

  if(ret != 0)
  {
    fprintf(stderr, "Failed to generate the DSA parameters\n");
    return ret;
  }

  ret = wc_MakeDsaKey(&rng, &dsaKey);

  if(ret != 0)
  {
    fprintf(stderr, "Failed to generate the DSA key pair\n");
    return ret;
  }


  ret = dsa_sign(&dsaKey, msg, msgLen, signature, WC_HASH_TYPE_SHA256);


  if(ret != 0)
  {
    fprintf(stderr, "Failed to generate the signature\n");
    return ret;
  }


  if (ret == 0)
  {
    /* Display message as a buffer */
    print_buffer("msg", msg, msgLen);
    printf("\n");
    /* Display binary signature as a buffer */
    print_buffer("dsa_signature", signature, sizeof(signature));
    printf("\n");
  }

  int verificationResult = 1;

  ret = dsa_verify(&dsaKey, msg, msgLen, signature, &verificationResult, WC_HASH_TYPE_SHA256);

  if (ret == 0)
  {
    if (verificationResult == 1)
    {
      printf("The signature is verified successfully\n");
    }
    else
    {
      printf("The signature verification failed\n");
    }
  }
  else
  {
    printf("Signature verification processing failed\n");
  }

  return ret == 0 ? 0 : 1;
}
