#include "decode.h"
#include "decrypt.h"
#include "subscribe.h"
#include "cryptosystem.h"

extern const kdf_node_t SUB0_NODE;
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
    if (verify_packet(packet, len) != 0) {
        send_error();
        return;
    }

    enc_frame_t * enc_frame = (enc_frame_t *)packet;

    // Check if we are subscribed
    subscription_t * subscription = find_subscription(enc_frame->channel, false);

    if (subscription != NULL || enc_frame->channel == 0) {
        // Check timestamp
        last_timestamp_t * entry = find_last_timestamp(enc_frame->channel);

        if (entry != NULL) {
            if ((entry->active && enc_frame->timestamp > entry->timestamp) || (!entry->active)) {
                // Find the correct decryption key
                kdf_node_t * kdf_node = &SUB0_NODE;
                if (enc_frame->channel != 0) {
                    kdf_node = find_ts_parent(subscription, enc_frame->timestamp);
                    if (kdf_node == NULL) {
                        send_error();
                        return;
                    }
                }

                aeskey_t frame_key = { 0 };
                int ret = derive_node_subkey(kdf_node, enc_frame->timestamp, &frame_key);
                if (ret != 0) {
                    send_error();
                    return;
                }

                // Decrypt
                uint16_t frame_len = 0;
                frame_t * frame = decrypt_frame(packet, len, &frame_key, &frame_len);

                // Send the frame
                if (frame != NULL && frame_len > 0 && frame_len <= MAX_FRAME_SIZE) {
                    if (send_packet(frame->data, frame_len, OPCODE_DECODE)) {
                        // For a successful decryption, update the entry
                        entry->active = true;
                        entry->channel = enc_frame->channel;
                        entry->timestamp = enc_frame->timestamp;
    
                        return;
                    }
                }
            }
        }
    }

    send_error();
}