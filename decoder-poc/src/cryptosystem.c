#include "cryptosystem.h"
#include <string.h>
#include <assert.h>

void init_pool(SubscriptionPool *pool) {
  memset(pool, 0, sizeof(pool));
}

ChannelSubscription *find_subscription(const SubscriptionPool *pool, channel_id_t channel) {
  for (int i = 0; i < NUM_CHANNELS; i++) {
    if (!pool->active[i]) continue;
    if (pool->subs[i].channel == channel) return &pool->subs[i];
  }
  return NULL;
}

node_t *find_node(const ChannelSubscription *sub, timestamp_t ts) {
  node_t *node;
  timestamp_t start, end;

  assert(sub->n_nodes <= SUBCRTIPION_MAX_NODES);
  for (int i = 0; i < sub->n_nodes; i++) {
    node = &sub->nodes[i];
    start = node->index << (TREE_DEPTH - node->level);
    if (ts < start) continue;
    end = ((node->index + 1) << (TREE_DEPTH - node->level)) - 1;
    // TODO: verify that [start, end] should be a closed range
    if (ts > end) continue;
    return node;
  }
  return NULL;
}
