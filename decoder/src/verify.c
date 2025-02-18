#include "verify.h"

// pubkey bytes corresponding to null private key
static uint8_t sk_bytes[32] = { 0x3b,0x6a,0x27,0xbc,0xce,0xb6,0xa4,0x2d,0x62,0xa3,0xa8,0xd0,0x2a,0x6f,0x0d,0x73,0x65,0x32,0x15,0x77,0x1d,0xe2,0x43,0xa6,0x3a,0xc0,0x48,0xa1,0x8b,0x59,0xda,0x29 };
static ed25519_key signing_key = {0};

int init_signing_key(void) {
    int ret = wc_ed25519_init(&signing_key);
    if (ret != 0) {
        return ret;
    }

    return wc_ed25519_import_public(sk_bytes, sizeof(sk_bytes), &signing_key);
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