#include "verify.h"

extern const uint8_t SK_BYTES[32];
static ed25519_key signing_key = {0};

int init_signing_key(void) {
    int ret = wc_ed25519_init(&signing_key);
    if (ret != 0) {
        return ret;
    }

    return wc_ed25519_import_public(SK_BYTES, sizeof(SK_BYTES), &signing_key);
}

int verify_packet(packet_t * packet, uint16_t len) {
    int ret;
    int verified;

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