#include "decode.h"

static last_timestamp_t last_timestamps[NUM_MAX_CHANNELS] = { 0 };

/** @brief Locate the last timestamp entry for a given channel
 * 
 *  @param channel: uint32_t, channel number of the timestamp entry to find
 * 
 *  @return last_timestamp_t *: pointer to the last timestamp entry OR an unused entry, NULL if not found
 */
last_timestamp_t * find_last_timestamp(uint32_t channel) {
    last_timestamp_t * entry;

    // Look for an active entry
    for (int i = 0; i < NUM_MAX_CHANNELS; i++) {
        entry = &last_timestamps[i];
        if (entry->active && entry->channel == channel) {
            return entry;
        }
    }

    // Find an open slot
    for (int i = 0; i < NUM_MAX_CHANNELS; i++) {
        entry = &last_timestamps[i];
        if (!entry->active) {
            return entry;
        }
    }

    return NULL;
}

/** @brief Handle decode command, returning a successfully decoded frame over UART
 * 
 *  @param packet: packet_t *, Pointer to the packet to be read from.
 *  @param len: uint16_t, Length of the packet in bytes.
 */
void decode(packet_t * packet, uint16_t len) {
    // Validate the packet
    // signature_offset = read - sizeof(signature_t);
    // signature = (signature_t *)&packet.rawBytes[signature_offset]
    // ed25519_verify(packet, signature_offset, signature)

    frame_t * frame = (frame_t *)packet->body;
    uint16_t frame_len = len - sizeof(header_t) - sizeof(uint32_t) - sizeof(uint64_t);

    // Check if we are subscribed
    subscription_t * subscription = find_subscription(frame->channel, false);

    if (subscription != NULL) {
        // Check timestamp
        last_timestamp_t * entry = find_last_timestamp(frame->channel);

        if (entry != NULL) {
            if ((entry->active && frame->timestamp > entry->timestamp) || (!entry->active)) {
                // Find the correct decryption key

                // Decrypt

                // Send the frame
                if (send_packet(frame->data, frame_len, OPCODE_DECODE)) {
                    // For a successful decryption, update the entry
                    entry->active = true;
                    entry->channel = frame->channel;
                    entry->timestamp = frame->timestamp;

                    return;
                }
            }
        }
    }

    send_error();
}