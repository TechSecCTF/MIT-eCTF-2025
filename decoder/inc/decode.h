/**
 * @file "decode.h"
 * @author MIT TechSec
 * @brief Frame decoding functions header
 * @date 2025
 *
 * @copyright Copyright (c) 2025 Massachusetts Institute of Technology
 */

#ifndef _DECODE_H
#define _DECODE_H

#include <stdint.h>
#include <stdbool.h>
#include "subscribe.h"

#define MAX_FRAME_SIZE 64

#pragma pack(push, 1)

typedef union {
    uint8_t data[MAX_FRAME_SIZE];
} frame_t;

#pragma pack(pop)

void decode(packet_t * packet, uint16_t len);

#endif