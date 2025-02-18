#include "subscribe.h"
#include "decrypt.h"
#include "verify.h"

subscription_t * subscriptions[NUM_MAX_SUBSCRIPTIONS] = {
    (subscription_t *)SUB1,
    (subscription_t *)SUB2,
    (subscription_t *)SUB3,
    (subscription_t *)SUB4,
    (subscription_t *)SUB5,
    (subscription_t *)SUB6,
    (subscription_t *)SUB7,
    (subscription_t *)SUB8,
};

/** @brief Locate a subscription file in memory
 * 
 *  @param channel: uint32_t, Channel number of the subscription to find.
 *  @param empty_ok: bool, Whether to return an open subscription slot.
 * 
 *  @return subscription_t *: pointer to the subscription file in memory, NULL if not found.
 */
subscription_t * find_subscription(uint32_t channel, bool empty_ok) {
    subscription_t * last_empty = NULL;

    for (int i = 0; i < NUM_MAX_SUBSCRIPTIONS; i++) {
        subscription_t * slot = subscriptions[i];
        if (slot->channel == 0)
            last_empty = slot;

        if (slot->channel == channel)
            return slot;
    }

    if (empty_ok)
        return last_empty;

    return NULL;
}

/** @brief Handle a received subscription update file
 * 
 *  @param packet: packet_t *, Pointer to the packet to be read from.
 *  @param len: uint16_t, Length of the packet in bytes.
 */
void subscribe(packet_t * packet, uint16_t len) {
    // Validate the packet
    if (verify_packet(packet, len) != 0)  {
        send_error();
        return;
    }

    // Decrypt into buffer
    uint16_t sub_len = 0;
    subscription_t * sub = decrypt_subscription(packet, len, &sub_len);

    // Sanity checks
    if (sub->channel == 0) {
        send_error();
        return;
    }

    // Find appropriate buf to copy into
    subscription_t * slot = find_subscription(sub->channel, true);

    if (slot != NULL) {
        // Erase the appropriate page
        flash_simple_erase_page((uint32_t)slot);
        flash_simple_write((uint32_t)slot, sub->rawBytes, sub_len);

        send_header(OPCODE_SUBSCRIBE, 0);
        return;
    }

    send_error();
}