#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/ed25519.h"

#define MAX_CHANNEL_COUNT 8
#define TREE_DEPTH sizeof(timestamp_t) * 8

#define timestamp_t uint64_t
#define channel_id_t uint32_t

#pragma pack(push, 1)
typedef struct {
    uint8_t left[16];
    uint8_t right[16];
} digest_t;

typedef struct {
    uint8_t bytes[16];
} aeskey_t;

typedef struct {
    uint8_t level;
    uint64_t index;
    aeskey_t key;
} node_t;

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
    uint8_t n_keys;
    node_t nodes[126];
} subscription_t;

typedef union {
    struct {
        bool active;
        channel_id_t channel;
        timestamp_t start;
        timestamp_t end;
        uint8_t n_keys;
        node_t nodes[126];
    };
    uint8_t rawBytes[sizeof(bool) + sizeof(channel_id_t) + sizeof(timestamp_t) + sizeof(timestamp_t) + sizeof(uint8_t) + sizeof(node_t)*126];
} channel_status_t;

#pragma pack(pop)

int find_subscription(channel_status_t * subscriptions, channel_id_t channel, timestamp_t timestamp, subscription_t ** subscription);
int find_node(subscription_t * subscription, timestamp_t timestamp, node_t ** node);
int get_frame_key(node_t * node, timestamp_t timestamp, aeskey_t * key);