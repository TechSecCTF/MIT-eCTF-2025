#ifndef _LIST_CMD_H
#define _LIST_CMD_H

#include <stdint.h>
#include "subscribe.h"

#pragma pack(push, 1)

typedef struct {
    uint32_t channel_id;
    uint64_t start;
    uint64_t end;
} subscription_entry_t;

typedef union {
    struct {
        uint32_t num_channels;
        subscription_entry_t entries[NUM_MAX_SUBSCRIPTIONS];
    };
    uint8_t rawBytes[sizeof(uint32_t) + sizeof(subscription_entry_t) * NUM_MAX_SUBSCRIPTIONS];
} list_response_t;

#define LIST_RESPONSE_SIZE(num_entries) (sizeof(uint32_t) + sizeof(subscription_entry_t) * num_entries)

#pragma pack(pop)

void list(void);

#endif