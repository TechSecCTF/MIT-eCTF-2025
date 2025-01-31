#include <stdio.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>

#include "secrets.h"


#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))
#define get_digest(in,out) wc_Sha256Hash((byte *)in, 16, (byte *)out)

int main(void) {
  wolfSSL_Debugging_ON();
  printf("Hello, world!\n");

  printf("%d\n", channels[0]);

  for (int i = 0; i < ARRAY_LEN(channels); i++) {
    printf("%d ", channels[i]);
  }
  printf("\n");

  char *data = "AAAA";
  byte hash[32];

  if (wc_Sha256Hash(data, 4, hash) != 0) {
    WOLFSSL_MSG("wc_Sha256Hash failed");
  }

  printf("Hash: ");
  for (int i = 0; i < ARRAY_LEN(hash); i++) {
    printf("%02x", hash[i]);
  }
  printf("\n");

  return 0;
}
