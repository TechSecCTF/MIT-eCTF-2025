#include "subscribe.h"
#include "decrypt.h"
#include "verify.h"

subscription_t * subscriptions[NUM_MAX_SUBSCRIPTIONS] = {
    (subscription_t *)FLASH_SUB1,
    (subscription_t *)FLASH_SUB2,
    (subscription_t *)FLASH_SUB3,
    (subscription_t *)FLASH_SUB4,
    (subscription_t *)FLASH_SUB5,
    (subscription_t *)FLASH_SUB6,
    (subscription_t *)FLASH_SUB7,
    (subscription_t *)FLASH_SUB8,
};

/** @brief Locate an existing subscription file in memory
 * 
 *  @param channel: channel_id_t, Channel number of the subscription to find.
 * 
 *  @return subscription_t *: pointer to the subscription file in memory, NULL if not found.
 */
subscription_t *find_matching_subscription(channel_id_t channel) {
    if (channel == 0) return NULL;

    for (int i = 0; i < NUM_MAX_SUBSCRIPTIONS; i++) {
        if (subscriptions[i]->channel == channel) return subscriptions[i];
    }

    return NULL;
}

/** @brief Locate a subscription file in memory
 * 
 *  @param channel: channel_id_t, Channel number of the subscription to find.
 * 
 *  @return subscription_t *: pointer to the subscription file in memory, NULL if not found.
 */
subscription_t *find_subscription_or_unused(channel_id_t channel) {
    if (channel == 0) return NULL;

    subscription_t *last_empty_slot = NULL;
    for (int i = 0; i < NUM_MAX_SUBSCRIPTIONS; i++) {
        if (subscriptions[i]->channel == 0) {
            last_empty_slot = subscriptions[i];
            continue;
        }

        if (subscriptions[i]->channel == channel) return subscriptions[i];
    }

    return last_empty_slot;
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

    if (sub != NULL && sub_len > 0) {
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
    }

    send_error();
}