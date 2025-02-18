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
    channel_id_t channel;
    timestamp_t timestamp;
} last_timestamp_t;

typedef union {
    uint8_t data[MAX_FRAME_SIZE];
} frame_t;

#pragma pack(pop)

void decode(packet_t * packet, uint16_t len);

#endif