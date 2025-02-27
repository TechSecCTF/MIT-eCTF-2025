#include "decrypt.h"
// #include "kdf.h"

extern const aeskey_t SUBSCRIPTION_KEY;
static uint8_t decrypt_buffer[BODY_LEN] = { 0 };

/** @brief Decrypt a frame.
 * 
 *  @param packet: packet_t *, Pointer to the encrypted packet.
 *  @param packet_len: uint16_t, Length of the encrypted packet in bytes.
 *  @param frame_key: uint8_t *, Pointer to the appropriate frame key.
 *  @param decrypted_len: uint16_t *, Store number of bytes decrypted.
 * 
 *  @return frame_t *: Pointer to the decrypted frame, NULL if decryption failed.
 */
frame_t * decrypt_frame(packet_t * packet, uint16_t packet_len, aeskey_t * frame_key, uint16_t * decrypted_len) {
    int ret;
    Aes ctx = { 0 };
    enc_frame_t * enc = (enc_frame_t *)packet;

    // Ensure packet is not larger than expected.
    if (packet_len > sizeof(packet_t)) {
        return NULL;
    }

    // Clear decryption buffer
    memset(decrypt_buffer, 0, sizeof(decrypt_buffer));

    // Initialize AES context
    ret = wc_AesGcmSetKey(&ctx, frame_key->bytes, KEY_LEN);
    if (ret != 0) {
        return NULL;
    }

    // Check for underflow
    uint16_t ct_len = packet_len - SIGNATURE_LEN - AUTHTAG_LEN - NONCE_LEN - sizeof(timestamp_t) - sizeof(channel_id_t) - sizeof(header_t);
    if (ct_len >= packet_len) {
        return NULL;
    }

    // Cross your fingers
    ret = wc_AesGcmDecrypt(&ctx, decrypt_buffer, enc->ciphertext, ct_len, enc->nonce, sizeof(enc->nonce), enc->tag, sizeof(enc->tag), enc->aad, sizeof(enc->aad));
    if (ret != 0) {
        return NULL;
    }

    *decrypted_len = ct_len;
    return (frame_t *)decrypt_buffer;
}

/** @brief Decrypt a subscription update file.
 * 
 *  @param packet: packet_t *, Pointer to the encrypted packet.
 *  @param packet_len: uint16_t, Length of the encrypted packet in bytes.
 *  @param decrypted_len: uint16_t *, Store number of bytes decrypted.
 * 
 *  @return subscription_t *: Pointer to the decrypted subscription file, NULL if decryption failed.
 */
subscription_t * decrypt_subscription(packet_t * packet, uint16_t packet_len, uint16_t * decrypted_len) {
    int ret;
    Aes ctx = { 0 };
    enc_subscription_t * enc = (enc_subscription_t *)packet;

    // Ensure packet is not larger than expected.
    if (packet_len > sizeof(packet_t)) {
        return NULL;
    }

    // Clear decryption buffer
    memset(decrypt_buffer, 0, sizeof(decrypt_buffer));

    // Initialize AES context
    ret = wc_AesGcmSetKey(&ctx, SUBSCRIPTION_KEY.bytes, sizeof(SUBSCRIPTION_KEY.bytes));
    if (ret != 0) {
        return NULL;
    }

    // Check for underflow
    uint16_t ct_len = packet_len - SIGNATURE_LEN - AUTHTAG_LEN - NONCE_LEN - sizeof(header_t);
    if (ct_len >= packet_len) {
        return NULL;
    }

    // Cross your fingers
    ret = wc_AesGcmDecrypt(&ctx, decrypt_buffer, enc->ciphertext, ct_len, enc->nonce, sizeof(enc->nonce), enc->tag, sizeof(enc->tag), enc->aad, sizeof(enc->aad));
    if (ret != 0) {
        return NULL;
    }

    *decrypted_len = ct_len;
    return (subscription_t *)decrypt_buffer;
}