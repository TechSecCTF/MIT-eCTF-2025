#include "verify.h"

extern const uint8_t SK_BYTES[32];
static ed25519_key signing_key = {0};

/** @brief Initialize wolfcrypt ed25519 signing key object.
 * 
 *  @return int: 0 on success, otherwise a wolfcrypt error code.
 */
int init_signing_key(void) {
    int ret = wc_ed25519_init(&signing_key);
    if (ret != 0) {
        return ret;
    }

    return wc_ed25519_import_public(SK_BYTES, sizeof(SK_BYTES), &signing_key);
}

/** @brief Verify a packet is signed with the encoder's signing key.
 * 
 *  @param packet: packet_t *, Pointer to the encrypted packet.
 *  @param len: uint16_t, Length of the encrypted packet in bytes.
 * 
 *  @return int: 0 on success, -1 on failure.
 */
int verify_packet(packet_t * packet, uint16_t len) {
    int ret;
    int verified;

    // Ensure packet is not larger than expected.
    if (len > sizeof(packet_t)) {
        return -1;
    }

    // Check for underflow
    if (len < SIGNATURE_LEN) {
        return -1;
    }

    byte * signature = &packet->rawBytes[len - SIGNATURE_LEN];

    ret = wc_ed25519_verify_msg(signature, SIGNATURE_LEN, packet->rawBytes, len - SIGNATURE_LEN, &verified, &signing_key);

    if (ret == 0 && verified == 1) {
        return 0;
    }

    return -1;
}