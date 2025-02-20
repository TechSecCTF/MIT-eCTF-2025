#ifndef _SUBSCRIBE_H
#define _SUBSCRIBE_H

#include <stdint.h>
#include "simple_flash.h"
#include "messaging.h"
#include "cryptosystem.h"

#define NUM_MAX_SUBSCRIPTIONS 8

#define SUB_FLASH_START 0x10036000
#define FLAHS_SUB1 (SUB_FLASH_START + (0 * MXC_FLASH_PAGE_SIZE))
#define FLASH_SUB2 (SUB_FLASH_START + (1 * MXC_FLASH_PAGE_SIZE))
#define FLASH_SUB3 (SUB_FLASH_START + (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_SUB4 (SUB_FLASH_START + (3 * MXC_FLASH_PAGE_SIZE))
#define FLASH_SUB5 (SUB_FLASH_START + (4 * MXC_FLASH_PAGE_SIZE))
#define FLASH_SUB6 (SUB_FLASH_START + (5 * MXC_FLASH_PAGE_SIZE))
#define FLASH_SUB7 (SUB_FLASH_START + (6 * MXC_FLASH_PAGE_SIZE))
#define FLASH_SUB8 (SUB_FLASH_START + (7 * MXC_FLASH_PAGE_SIZE))

#pragma pack(push, 1)

#pragma pack(pop)

subscription_t *find_matching_subscription(channel_id_t channel);
subscription_t *find_subscription_or_unused(channel_id_t channel);
void subscribe(packet_t * packet, uint16_t len);

#endif