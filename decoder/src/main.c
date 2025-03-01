/**
 * @file "main.c"
 * @author MIT TechSec
 * @brief Initialization and main loop for the Decoder
 * @date 2025
 *
 * @copyright Copyright (c) 2025 Massachusetts Institute of Technology
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mxc_device.h"
#include "board.h"
#include "mxc_delay.h"
#include "mpu_armv7.h"

#include "simple_uart.h"
#include "simple_flash.h"

#include "messaging.h"
#include "list_cmd.h"
#include "subscribe.h"
#include "decode.h"
#include "verify.h"

#include "led.h"
#define STATUS_LED_OFF(void) LED_Off(LED1); LED_Off(LED2); LED_Off(LED3);
#define STATUS_LED_RED(void) STATUS_LED_OFF(); LED_On(LED1);

void panic(void) {
    STATUS_LED_RED()
    while (true);
}

#define FIRST_BOOT_FLAG_PAGE 0x10040000
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

/** @brief Initialize the ARM MPU, disabling execution in most of SRAM.
 */
void setup_mpu(void) {
    // Application code [0x1000_0000, 0x1004_0000] RX
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(0, 0x10000000),
        ARM_MPU_RASR(0, ARM_MPU_AP_PRO, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_256KB)
    );

    // Subscriptions [0x1004_0000, 0x1008_0000] RW
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(1, 0x10040000),
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_256KB)
    );

    // SRAM [0x2000_0000, 0x2000_2000] RW
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(2, 0x20000000),
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_8KB)
    );

    // Flashprog [0x2000_2000, 0x2000_4000] RX
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(3, 0x20002000),
        ARM_MPU_RASR(0, ARM_MPU_AP_PRO, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_8KB)
    );

    // SRAM [0x2000_4000, 0x2000_8000] RW
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(4, 0x20004000),
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_16KB)
    );

    // SRAM [0x2000_8000, 0x2001_0000] RW
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(5, 0x20008000),
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_32KB)
    );

    // SRAM [0x2001_0000, 0x2002_0000] RW
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(6, 0x20010000),
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_64KB)
    );

    // Peripherals [0x4000_0000, 0x6000_0000] RW
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(7, 0x40000000),
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_512MB)
    );

    // Enable MPU with all region definitions and background regions
    // for privileged access. Exceptions are protected by MPU.
    ARM_MPU_Enable(MPU_CTRL_PRIVDEFENA_Msk | MPU_CTRL_HFNMIENA_Msk);
}

void init(void) {
    // Initialize ARM MPU
    setup_mpu();

    // Free speed boost by using the 100MHz Internal Primary Oscillator
    // src: msdk-2024_02/Libraries/PeriphDrivers/Source/SYS/sys_me17.c
    if (MXC_SYS_Clock_Select(MXC_SYS_CLOCK_IPO) != 0) panic();

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Clear subscription pages on first boot
    clear_subscription_pages();

    // Initialize signing key
    if (init_signing_key() < 0) panic();

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
                list(&packet);
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