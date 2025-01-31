#include <stdint.h>
// #include <stdbool.h>

#include "secrets.h"

typedef uint64_t timestamp_t;
typedef uint32_t channel_id_t;

// n depth tree can store 2^n nodes
// ...therefore depth = bitcount of the type
#define TREE_DEPTH sizeof(timestamp_t) * 8
// worst case = 2 nodes per level, minus the top level
#define SUBCRTIPION_MAX_NODES 2 * TREE_DEPTH - 2

#pragma pack(push, 1)

typedef struct aeskey
{
  uint8_t bytes[16];
} aeskey_t;

typedef struct key_node
{
  uint8_t level;
  uint64_t index;
  aeskey_t key;
} node_t;

typedef union
{
  struct
  {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
    uint8_t n_nodes;
    node_t nodes[SUBCRTIPION_MAX_NODES];
  };
  uint8_t rawBytes[sizeof(channel_id_t) + sizeof(timestamp_t) + sizeof(timestamp_t) + sizeof(uint8_t) + sizeof(node_t) * 126];
} ChannelSubscription;

typedef struct subscription_pool
{
  ChannelSubscription subs[NUM_CHANNELS];
  bool active[NUM_CHANNELS];
} SubscriptionPool;

#pragma pack(pop)

void init_pool(SubscriptionPool *pool);
ChannelSubscription *find_subscription(const SubscriptionPool *pool, channel_id_t channel);
node_t *find_node(const ChannelSubscription *sub, timestamp_t ts);
