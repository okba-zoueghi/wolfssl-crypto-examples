#include "rsa_priv_2048.h"
#include "rsa_sign_ssa_pkcs_v_1_5.h"

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

  RsaKey         rsaKey;
  int idx;

  byte signature[2048/8];
  int sigLen;

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

  /* Initialize RSA key and random (if required) */
  if (ret == 0)
  {
    ret = wc_InitRsaKey(&rsaKey, NULL);
  }
  else
  {
    printf("wc_InitRsaKey failed\n");
  }

  /* Load DER encoded RSA private key from buffer */
  if (ret == 0)
  {
    idx = 0;
    ret = wc_RsaPrivateKeyDecode(private_key_2048, &idx, &rsaKey,
                                 sizeof(private_key_2048));
  }
  else
  {
    printf("wc_RsaPrivateKeyDecode failed\n");
  }

  ret = rsa_sign_ssa_pkcs_v_1_5(&rsaKey, msg, msgLen, signature, sizeof(signature), WC_HASH_TYPE_SHA256);


  if (ret >= 0)
  {
    sigLen = ret;
    ret = 0;
  }
  else
  {
    printf("wc_RsaSSL_Sign failed %d\n", ret);
  }


  if (ret == 0)
  {
    /* Display message as a buffer */
    print_buffer("msg", msg, msgLen);
    printf("\n");
    /* Display binary signature as a buffer */
    print_buffer("rsa_sig_2048", signature, sigLen);
  }

  return ret == 0 ? 0 : 1;
}
