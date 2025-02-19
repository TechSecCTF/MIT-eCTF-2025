#ifndef _DECODE_H
#define _DECODE_H

#include <stdint.h>
#include <stdbool.h>
#include "subscribe.h"

#define NUM_MAX_CHANNELS NUM_MAX_SUBSCRIPTIONS + 1
#define MAX_FRAME_SIZE 64

#pragma pack(push, 1)

typedef struct {
    bool active;
    uint32_t channel;
    uint64_t timestamp;
} last_timestamp_t;

typedef union {
    struct {
        uint32_t channel;
        uint64_t timestamp;
        uint8_t data[MAX_FRAME_SIZE];
    };
    uint8_t rawBytes[sizeof(uint32_t) + sizeof(uint64_t) + MAX_FRAME_SIZE];
} frame_t;

#pragma pack(pop)

void decode(packet_t * packet, uint16_t len);

#endif