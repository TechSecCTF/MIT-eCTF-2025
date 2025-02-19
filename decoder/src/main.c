#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mxc_device.h"
#include "board.h"
#include "mxc_delay.h"

#include "simple_uart.h"
#include "simple_flash.h"

#include "messaging.h"
#include "list_cmd.h"
#include "subscribe.h"
#include "decode.h"

#include "led.h"
#define STATUS_LED_OFF(void) LED_Off(LED1); LED_Off(LED2); LED_Off(LED3);
#define STATUS_LED_RED(void) STATUS_LED_OFF(); LED_On(LED1);

void panic(void) {
    STATUS_LED_RED()
    while (true);
}

#define FIRST_BOOT_FLAG_PAGE 0x10034000
#define FIRST_BOOT_FLAG 0xAAAAAAAA
extern subscription_t * subscriptions[NUM_MAX_SUBSCRIPTIONS];

/** @brief Write zeroes to subscription update file pages on first boot.
 */
void clear_subscription_pages(void) {
    uint8_t zeroes[MXC_FLASH_PAGE_SIZE] = {0};
    uint32_t flag = FIRST_BOOT_FLAG;
    if (flag == *(uint32_t *)FIRST_BOOT_FLAG_PAGE) {
        return;
    }

    flash_simple_erase_page((uint32_t)FIRST_BOOT_FLAG_PAGE);
    flash_simple_write((uint32_t)FIRST_BOOT_FLAG_PAGE, &flag, sizeof(uint32_t));

    for (int i = 0; i < NUM_MAX_SUBSCRIPTIONS; i++) {
        uint32_t address = (uint32_t)subscriptions[i];
        flash_simple_erase_page(address);
        flash_simple_write(address, zeroes, MXC_FLASH_PAGE_SIZE);
    }
}

void init(void) {
    // Free speed boost by using the 100MHz Internal Primary Oscillator
    // src: msdk-2024_02/Libraries/PeriphDrivers/Source/SYS/sys_me17.c
    if (MXC_SYS_Clock_Select(MXC_SYS_CLOCK_IPO) != 0) panic();

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Clear subscription pages on first boot
    clear_subscription_pages();

    // Initialize the uart peripheral to enable serial I/O
    if (uart_init() < 0) panic();
}

int main(void) {
    int read = 0;
    packet_t packet = {0};

    init();

    while (true) {
        // Read a packet
        read = read_packet(&packet);

        // If we read an invalid packet, then continue and read another packet.
        if (read == 0) {
            continue;
        }

        // Parse the packet for a valid header.
        switch (packet.header.opcode) {
            case OPCODE_LIST:
                list();
                continue;
            case OPCODE_SUBSCRIBE:
                subscribe(&packet, read);
                continue;
            case OPCODE_DECODE:
                decode(&packet, read);
                continue;
            default:
                send_error();
        };
    };  
}