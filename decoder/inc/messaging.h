#ifndef _MESSAGING_H
#define _MESSAGING_H

#include <stdint.h>
#include "simple_uart.h"

#define BODY_LEN 4096

#define MAGIC_BYTE 0x25
#define OPCODE_DECODE 0x44
#define OPCODE_SUBSCRIBE 0x53
#define OPCODE_LIST 0x4C
#define OPCODE_ACK 0x41
#define OPCODE_ERROR 0x45
#define OPCODE_DEBUG 0x47

#define PACKET_LEN sizeof(packet_t)

#pragma pack(push, 1)

typedef union {
    struct {
        uint8_t magic;
        uint8_t opcode;
        uint16_t length;
    };
    uint8_t rawBytes[4];
} header_t;

typedef union {
    struct {
        header_t header;
        uint8_t body[BODY_LEN];
    };
    uint8_t rawBytes[BODY_LEN + sizeof(header_t)];
} packet_t;

#pragma pack(pop)

#define send_ack() send_header(OPCODE_ACK, 0)
#define send_error() send_header(OPCODE_ERROR, 0)

int read_packet(packet_t * packet);
int send_packet(uint8_t * buf, uint16_t len, uint8_t opcode);

bool send_header(uint8_t opcode, uint16_t len);
bool read_ack(void);

int read_bytes(uint8_t * buf, uint16_t len);
int send_bytes(uint8_t * buf, uint16_t len);

#endif