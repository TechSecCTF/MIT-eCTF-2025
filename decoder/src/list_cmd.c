/**
 * @file "list_cmd.c"
 * @author MIT TechSec
 * @brief List command implementation
 * @date 2025
 *
 * @copyright Copyright (c) 2025 Massachusetts Institute of Technology
 */

#include <stdint.h>
#include "list_cmd.h"

extern subscription_t * subscriptions[NUM_MAX_SUBSCRIPTIONS];

/** @brief Handle list command, returning all active subscriptions over UART
 */
void list(void) {
    list_response_t response = {0};
    int curr = 0;
    for (int i = 0; i < NUM_MAX_SUBSCRIPTIONS; i++) {
        subscription_t * slot = subscriptions[i];
        if (slot->channel) {
            response.entries[curr].channel_id = slot->channel;
            response.entries[curr].start = slot->start;
            response.entries[curr].end = slot->end;
            curr++;
        }
    }
    response.num_channels = curr;

    send_packet(response.rawBytes, sizeof(uint32_t) + sizeof(subscription_entry_t)*curr, OPCODE_LIST);
}