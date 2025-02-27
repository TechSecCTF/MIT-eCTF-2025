#include "decode.h"
#include "decrypt.h"
#include "subscribe.h"
#include "cryptosystem.h"

extern const kdf_node_t SUB0_NODE;

// Use a bool to track if we've decoded any frame yet,
// so as to not assume magic values of last_timestamp being OK
// to ignore SR3.
static bool decoded_anything = false;
static timestamp_t last_timestamp = 0;

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
        if ((decoded_anything == false) || (enc_frame->timestamp > last_timestamp)) {
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
                // For a successful decryption, update last_timestamp.
                decoded_anything = true;
                last_timestamp = enc_frame->timestamp;

                send_packet(frame->data, frame_len, OPCODE_DECODE);
                return;
            }
        }
    }

    send_error();
}