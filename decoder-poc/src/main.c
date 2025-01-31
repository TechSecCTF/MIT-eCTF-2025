#include <stdio.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>

#include "secrets.h"


#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))
#define get_digest(in,out) wc_Sha256Hash((byte *)in, 16, (byte *)out)

int main(void) {
  wolfSSL_Debugging_ON();
  

  return 0;
}
