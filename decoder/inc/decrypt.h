#ifndef _DECRYPT_H
#define _DECRYPT_H

#include "subscribe.h"
#include "verify.h"
#include "messaging.h"
#include "decode.h"

#include "wolfssl/wolfcrypt/aes.h"

#define NONCE_LEN 12
#define AUTHTAG_LEN 16

#pragma pack(push, 1)

typedef union {
    struct {
        union {
            struct {
                header_t header;
                channel_id_t channel;
                timestamp_t timestamp;
                uint8_t nonce[NONCE_LEN];
            };
            uint8_t aad[sizeof(header_t) + sizeof(channel_id_t) + sizeof(timestamp_t) + NONCE_LEN];
        };
        uint8_t tag[AUTHTAG_LEN];
        uint8_t ciphertext[BODY_LEN - sizeof(header_t) - sizeof(channel_id_t) - sizeof(timestamp_t) - NONCE_LEN - AUTHTAG_LEN];
    };
    uint8_t rawBytes[BODY_LEN];
} enc_frame_t;

typedef union {
    struct {
        union {
            struct {
                header_t header;
                uint8_t nonce[NONCE_LEN];
            };
            uint8_t aad[sizeof(header_t) + NONCE_LEN];
        };
        uint8_t tag[AUTHTAG_LEN];
        uint8_t ciphertext[BODY_LEN - sizeof(header_t) - NONCE_LEN - AUTHTAG_LEN];
    };
    uint8_t rawBytes[BODY_LEN];
} enc_subscription_t;

#pragma pack(pop)

frame_t * decrypt_frame(packet_t * packet, uint16_t packet_len, aeskey_t * frame_key, uint16_t * decrypted_len);
subscription_t * decrypt_subscription(packet_t * packet, uint16_t packet_len, uint16_t * decrypted_len);

#endif