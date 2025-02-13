#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>

#include "cryptosystem.h"
#include "secrets.h"


#define ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))
#define get_digest(in,out) wc_Sha256Hash((byte *)in, 16, (byte *)out)

void hex_to_bytes(const char *hex, unsigned char *bytes, size_t *len) {
  size_t hex_len = strlen(hex);
  
  if (hex_len % 2 != 0) {
    fprintf(stderr, "error: hex string must have an even length.\n");
    exit(2);
  }

  *len = hex_len / 2;
  for (size_t i = 0; i < *len; i++) {
    if (!isxdigit(hex[2 * i]) || !isxdigit(hex[2 * i + 1])) {
        fprintf(stderr, "error: invalid hex character detected.\n");
        exit(EXIT_FAILURE);
    }
    sscanf(&hex[2 * i], "%2hhx", &bytes[i]);
  }
}

int main(int argc, char *argv[]) {
  wolfSSL_Debugging_ON();
  if (wolfCrypt_Init() != 0) {
    WOLFSSL_MSG("wolfCrypt_Init() error");
  }

  if (argc < 3) {
    fprintf(stderr, "Usage: %s <channel> <subscription hex>\n", argv[0]);
    return 1;
  }

  long channel = strtol(argv[1], NULL, 10);
  if (channel >= NUM_CHANNELS) {
    fprintf(stderr, "error: channel too big\n");
    return 1;
  }

  unsigned char subscription[4096] = {0};
  size_t sub_len = sizeof(subscription);
  hex_to_bytes(argv[2], subscription, &sub_len);
  printf("We got a %zu byte subscription\n", sub_len);
  if (sub_len > sizeof(ChannelSubscription)) {
    fprintf(stderr, "error: subscription too long\n");
    return 1;
  }

  SubscriptionPool pool;
  init_pool(&pool);
  memcpy(&pool.subs[channel], subscription, sizeof(ChannelSubscription));
  pool.active[channel] = true;

  timestamp_t ts = 0;
  kdf_node_t *parent_node = find_ts_parent(&pool.subs[channel], ts);
  if (parent_node == NULL) {
    fprintf(stderr, "error: no subscription to frame %ld\n", ts);
    return 1;
  }

  aeskey_t key;
  int ret = derive_node_subkey(parent_node, ts, &key);
  if (ret != 0) {
    fprintf(stderr, "error: unknown error in derive_node_subkey\n");
    return 1;
  }

  printf("Byte array: ");
  for (size_t i = 0; i < sizeof(key); i++) {
      printf("%02x", key.bytes[i]);
  }
  printf("\n");

  if (wolfCrypt_Cleanup() != 0) {
    WOLFSSL_MSG("wolfCrypt_Cleanup() error");
  }
  return 0;
}
