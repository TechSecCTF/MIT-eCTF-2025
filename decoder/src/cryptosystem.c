#include "cryptosystem.h"

#define get_digest(in,out) wc_Sha256Hash((byte *)in, 16, (byte *)out)

// iterate over subscriptions to identify one that has our channel and timestamp
int find_subscription(channel_status_t * subscriptions, channel_id_t channel, timestamp_t timestamp, subscription_t ** subscription) {
    int i;
    channel_status_t * curr;
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        curr = &subscriptions[i];
        if ((curr->channel == channel && curr->start <= timestamp && timestamp <= curr->end)) {
            *subscription = (subscription_t *)((void *)curr + 1);
            return 0;
        }
    }

    return -1;
}

int find_node(subscription_t * subscription, timestamp_t timestamp, node_t ** node) {
    int i;
    node_t * curr;
    timestamp_t start, end;

    // For each node in the subscription
    for (i = 0; i < subscription->n_keys; i++) {
        curr = &subscription->nodes[i];
        // Check if timestamp can be reached from given node
        start = curr->index << (TREE_DEPTH - curr->level);
        end = ((curr->index + 1) << (TREE_DEPTH - curr->level)) - 1;
        if (start <= timestamp && timestamp <= end) {
            *node = curr;
            break;
        }
    }

    return (i != subscription->n_keys) ? 0 : -1;
}

int get_frame_key(node_t * node, timestamp_t timestamp, aeskey_t * key) {
    int ret;
    node_t scratch = *node;
    node_t * curr = &scratch;
    timestamp_t start, end;
    digest_t digest = {0};

    // While the current node is not max depth
    while (curr->level != TREE_DEPTH) {
        // Get the digest of the current key
        ret = get_digest(&curr->key, &digest);
        if (ret) {
            return -1;
        }

        // Decide to go left or right...
        start = curr->index << (TREE_DEPTH - curr->level);
        end = ((curr->index + 1) << (TREE_DEPTH - curr->level)) - 1;
        curr->level += 1;
        // If timestamp is closer to start, descend left
        if (timestamp - start < end - timestamp) {
            curr->index = 2 * curr->index;
            memcpy(&curr->key, digest.left, 16);
        } else {
            curr->index = (2 * curr->index) + 1;
            memcpy(&curr->key, digest.right, 16);
        }
    }

    *key = curr->key;

    return (curr->level == TREE_DEPTH) ? 0 : -1;
}


