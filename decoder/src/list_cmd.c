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
 * 
 *  @param packet: packet_t *, Pointer to the packet.
 */
void list(packet_t * packet) {
    // Error on list commands with a body
    if (packet->header.length != 0) {
        send_error();
        return;
    }

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