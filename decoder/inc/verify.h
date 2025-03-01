/**
 * @file "verify.h"
 * @author MIT TechSec
 * @brief Packet verification functions header
 * @date 2025
 *
 * @copyright Copyright (c) 2025 Massachusetts Institute of Technology
 */

#ifndef _VERIFY_H
#define _VERIFY_H

#include "messaging.h"
#include "wolfssl/wolfcrypt/ed25519.h"

#define SIGNATURE_LEN 64

int init_signing_key(void);
int verify_packet(packet_t * packet, uint16_t len);

#endif