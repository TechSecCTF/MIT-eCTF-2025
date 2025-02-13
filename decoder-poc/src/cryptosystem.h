#include <stdint.h>
#include <stdbool.h>
#include <wolfssl/wolfcrypt/hash.h>

#include "secrets.h"

typedef uint64_t timestamp_t;
typedef uint32_t channel_id_t;

// n depth tree can store 2^n nodes
// ...therefore depth = bitcount of the type
#define KDF_TREE_DEPTH sizeof(timestamp_t) * 8
// worst case = 2 nodes per level, minus the top level
#define SUBCRTIPION_MAX_NODES 2 * KDF_TREE_DEPTH - 2

#pragma pack(push, 1)

typedef struct aeskey
{
  uint8_t bytes[16];
} aeskey_t;

#define KDF_DIGEST_SIZE SHA256_DIGEST_SIZE
typedef union
{
  struct {
    uint8_t left[sizeof(aeskey_t)];
    uint8_t right[sizeof(aeskey_t)];
  };
  byte rawDigest[KDF_DIGEST_SIZE];
} digest_t;

typedef struct kdf_node
{
  uint8_t level;
  uint64_t index;
  aeskey_t key;
} kdf_node_t;

typedef union
{
  struct
  {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
    uint8_t n_nodes;
    kdf_node_t nodes[SUBCRTIPION_MAX_NODES];
  };
  uint8_t rawBytes[sizeof(channel_id_t) + sizeof(timestamp_t) + sizeof(timestamp_t) + sizeof(uint8_t) + sizeof(kdf_node_t) * 126];
} ChannelSubscription;

typedef struct subscription_pool
{
  ChannelSubscription subs[NUM_CHANNELS];
  bool active[NUM_CHANNELS];
} SubscriptionPool;

#pragma pack(pop)

int calc_kdf_digest(const byte *in, word32 len, digest_t *out);

void init_pool(SubscriptionPool *pool);

ChannelSubscription *find_subscription(SubscriptionPool *pool, channel_id_t channel);

kdf_node_t *find_ts_parent(ChannelSubscription *sub, timestamp_t ts);

int derive_node_subkey(const kdf_node_t *ts_node, timestamp_t ts, aeskey_t *out_key);
