/**
 * @file "cryptosystem.c"
 * @author MIT TechSec
 * @brief Frame key derivation and subscriptions parsing functions
 * @date 2025
 *
 * @copyright Copyright (c) 2025 Massachusetts Institute of Technology
 */

#include "cryptosystem.h"
#include "wolfssl/wolfcrypt/hash.h"
#include <string.h>

int calc_kdf_digest(const byte *in, word32 len, digest_t *digest) {
  return wc_Sha256Hash(in, len, (byte*) &digest->rawDigest);
}

#ifdef _DECODER_POC

void init_pool(SubscriptionPool *pool) {
  memset(pool, 0, sizeof(*pool));
}

subscription_t *find_subscription(SubscriptionPool *pool, channel_id_t channel) {
  for (int i = 0; i < NUM_CHANNELS; i++) {
    if (!pool->active[i]) continue;
    if (pool->subs[i].channel == channel) return &pool->subs[i];
  }
  return NULL;
}

#endif

// find which node within our subscription is a parent of ts
kdf_node_t *find_ts_parent(subscription_t *sub, timestamp_t ts) {
  kdf_node_t *node;
  timestamp_t start, end;

  if (sub->n_nodes <= SUBSCRIPTION_MAX_NODES) {
    for (int i = 0; i < sub->n_nodes; i++) {
      node = &sub->nodes[i];
      start = node->index << (KDF_TREE_DEPTH - node->level);
      if (ts < start) continue;
      end = ((node->index + 1) << (KDF_TREE_DEPTH - node->level)) - 1;
      if (ts > end) continue;
      return node;
    }
  }
  return NULL;
}

// derive key from node that is a parent for ts
int derive_node_subkey(const kdf_node_t *parent, timestamp_t ts, aeskey_t *out_key) {
  kdf_node_t curr = *parent;
  digest_t digest = {0};

  while (curr.level < KDF_TREE_DEPTH) {
    int ret = calc_kdf_digest((byte*) &curr.key.bytes, sizeof(curr.key), &digest);
    if (ret != 0) {
      return -1;
    }

    // Decide to go left or right...
    timestamp_t start = curr.index << (KDF_TREE_DEPTH - curr.level);
    timestamp_t end = ((curr.index + 1) << (KDF_TREE_DEPTH - curr.level)) - 1;
    curr.level += 1;
    // If timestamp is closer to start, descend left
    if (ts - start < end - ts) {
      curr.index = 2 * curr.index;
      memcpy(&curr.key, digest.left, sizeof(digest.left));
    } else {
      curr.index = 2 * curr.index + 1;
      memcpy(&curr.key, digest.right, sizeof(digest.left));
    }
  }

  memcpy(out_key->bytes, &curr.key, sizeof(out_key->bytes));
  return 0;
}
