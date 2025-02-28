#include "messaging.h"

/** @brief Read a well-formed packet over UART.
 * 
 *  @param packet: packet_t *, Pointer to the packet to be read into.
 * 
 *  @return int: Number of bytes read into the packet.
 */
int read_packet(packet_t * packet) {
    int read = 0;
    memset(packet, 0, sizeof(packet_t));

    // Read the Header
    read += read_bytes(packet->rawBytes, sizeof(header_t));

    // Read the Body
    if (packet->header.length <= BODY_LEN) {
        read += read_bytes(packet->body, packet->header.length);
        return read;
    }

    // If we receive an unexpectedly large packet, just discard the bytes so that
    // we can easily continue receiving packets. Mostly so a lack of this isn't
    // construed as an attempt to lock out an attacker.
    for (uint16_t i = 0; i < packet->header.length; i++) {
        if (i && i % 256 == 0) {
            send_ack();
        }
        uart_readbyte();
    }
    send_ack();

    memset(packet, 0, sizeof(packet_t));
    send_error();
    return 0;
}

/** @brief Send a well-formed packet over UART.
 * 
 *  @param buf: uint8_t *, Pointer to packet body to read from.
 *  @param len: uint16_t, Number of bytes from body to read.
 *  @param opcode: uint8_t, Command opcode to include in header.
 * 
 *  @return int: Number of bytes of body written.
 */
int send_packet(uint8_t * buf, uint16_t len, uint8_t opcode) {
    if (!send_header(opcode, len)) {
        return 0;
    }

    return send_bytes(buf, len);
}

/** @brief Send a packet header over UART.
 * 
 *  @param opcode: uint8_t, Command opcode to include in header.
 *  @param len: uint16_t, Len field of header.
 * 
 *  @return bool: true if header was properly ACK'd, else false.
 */
bool send_header(uint8_t opcode, uint16_t len) {
    uart_writebyte(MAGIC_BYTE);
    uart_writebyte(opcode);
    uart_writebyte(len & 0xff);
    uart_writebyte(len >> 8);
    if (opcode == OPCODE_ACK) {
        return true;
    }
    return read_ack();
}

/** @brief Read an ACK.
 * 
 *  @return bool: true if we read a proper ACK, else false.
 */
bool read_ack(void) {
    if (uart_readbyte() == MAGIC_BYTE) {
        if (uart_readbyte() == OPCODE_ACK) {
            if (uart_readbyte() == 0) {
                if (uart_readbyte() == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

/** @brief Read bytes over UART.
 * 
 *  @param buf: uint8_t *, Buffer to read bytes into.
 *  @param len: uint16_t, Number of bytes to read.
 * 
 *  @return int: Number of bytes read.
 */
int read_bytes(uint8_t * buf, uint16_t len) {
    int i = 0;
    if (len > BODY_LEN) {
        len = BODY_LEN;
    } else if (len == 0) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        if (i && i % 256 == 0) {
            send_ack();
        }
        buf[i] = (uint8_t)uart_readbyte();
    }

    send_ack();

    return i;
}

/** @brief Send bytes over UART.
 * 
 *  @param buf: uint8_t *, Buffer to read bytes from.
 *  @param len: uint16_t, Number of bytes to send.
 * 
 *  @return int: Number of bytes sent.
 */
int send_bytes(uint8_t * buf, uint16_t len) {
    int i = 0;
    if (len > BODY_LEN) {
        len = BODY_LEN;
    } else if (len == 0) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        if (i && i % 256 == 0) {
            if (!read_ack()) {
                send_error();
                memset(buf, 0, len);
                return i;
            }
        }
        uart_writebyte(buf[i]);
    }

    read_ack();

    memset(buf, 0, len);
    return i;
}
