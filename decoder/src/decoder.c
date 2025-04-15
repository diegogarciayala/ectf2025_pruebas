#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT 0xDEADBEEF

#define FLASH_DEVICE_ID_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4 * MXC_FLASH_PAGE_SIZE))
#define FLASH_STATUS_ADDR    ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

#pragma pack(push, 1)
typedef struct {
    channel_id_t channel;
    timestamp_t  timestamp;
    uint8_t      data[FRAME_SIZE];
} frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t  start_timestamp;
    timestamp_t  end_timestamp;
    channel_id_t channel;
} subscription_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t  start;
    timestamp_t  end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop)

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot;
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

flash_entry_t decoder_status;
char output_buf[128];

#ifndef DECODER_ID
#define DECODER_ID 0xDEADBEEF
#endif

decoder_id_t DEVICE_ID = DECODER_ID;

bool is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL) {
        return true;
    }
    time_t now = time(NULL);
    if (now < 0) now = 0;
    timestamp_t current_time = (timestamp_t)now;
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active &&
            decoder_status.subscribed_channels[i].id == channel &&
            decoder_status.subscribed_channels[i].start_timestamp <= current_time &&
            decoder_status.subscribed_channels[i].end_timestamp   >= current_time) {
            return true;
        }
    }
    return false;
}

void list_channels() {
    list_response_t resp = {0};
    resp.channel_info[0].channel = EMERGENCY_CHANNEL;
    resp.channel_info[0].start = 0;
    resp.channel_info[0].end = 0xFFFFFFFFFFFFFFFF;
    uint32_t channel_count = 1;
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[channel_count++] = (channel_info_t){
                .channel = decoder_status.subscribed_channels[i].id,
                .start = decoder_status.subscribed_channels[i].start_timestamp,
                .end = decoder_status.subscribed_channels[i].end_timestamp
            };
        }
    }
    resp.n_channels = channel_count;
    write_packet(LIST_MSG, &resp, sizeof(uint32_t) + channel_count * sizeof(channel_info_t));
}

void simple_decrypt(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= ((DEVICE_ID >> ((i % 4) * 8)) & 0xFF);
    }
}

int decode(pkt_len_t frame_len, frame_packet_t *frame) {
    if (!is_subscribed(frame->channel)) {
        print_error("Channel not subscribed");
        return -1;
    }
    simple_decrypt(frame->data, FRAME_SIZE);
    write_packet(DECODE_MSG, frame->data, FRAME_SIZE);
    msg_type_t ack;
    uint16_t ack_len;
    read_packet(&ack, NULL, &ack_len);
    return 0;
}

void handle_subscription(uint8_t *data) {
    subscription_update_packet_t *sub = (subscription_update_packet_t *)(data + 8);
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (!decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i] = (channel_status_t){
                .id = sub->channel,
                .start_timestamp = sub->start_timestamp,
                .end_timestamp = sub->end_timestamp,
                .active = true
            };
            flash_simple_erase_page(FLASH_STATUS_ADDR);
            flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
            write_packet(ACK_MSG, NULL, 0);
            return;
        }
    }
    print_error("No space for new subscription");
}

void init() {
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        memset(decoder_status.subscribed_channels, 0, sizeof(decoder_status.subscribed_channels));
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
    }
    uart_init();
}

int main(void) {
    uint8_t uart_buf[128];
    msg_type_t cmd;
    uint16_t pkt_len;
    init();
    while (1) {
        read_packet(&cmd, uart_buf, &pkt_len);
        switch (cmd) {
            case LIST_MSG:
                list_channels();
                break;
            case DECODE_MSG:
                decode(pkt_len, (frame_packet_t *)uart_buf);
                break;
            case SUBSCRIBE_MSG:
                handle_subscription(uart_buf);
                break;
            default:
                print_error("Unknown command");
                break;
        }
    }
}
