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
#define EMERGENCY_CHANNEL 1
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT 0xDEADBEEF

#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32
#define CMAC_SIZE 16
#define ENCODER_ID_SIZE 8
#define NONCE_SIZE 8
#define HEADER_SIZE 16

#define FLASH_DEVICE_ID_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4 * MXC_FLASH_PAGE_SIZE))
#define FLASH_STATUS_ADDR    ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_KEYS_ADDR      ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (3 * MXC_FLASH_PAGE_SIZE))

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
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

typedef struct {
    uint32_t seq_num;
    uint32_t channel;
    uint8_t  encoder_id[8];
    uint8_t  encrypted_data[];
} encoded_frame_t;

typedef struct {
    uint8_t master_key[KEY_SIZE];
    uint8_t signature_key[KEY_SIZE];
    uint8_t encoder_id[ENCODER_ID_SIZE];
} decoder_keys_t;
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
uint32_t last_seq_num = 0;
decoder_keys_t decoder_keys;
uint8_t channel_keys[MAX_CHANNEL_COUNT][KEY_SIZE];
char output_buf[128];

#ifndef DECODER_ID
#define DECODER_ID 0xDEADBEEF
#endif

decoder_id_t DEVICE_ID = DECODER_ID;

void boot_flag() {
    char flag_buf[64];
    sprintf(flag_buf, "boot flag: %p", boot_flag);
    print_debug(flag_buf);
}

void create_nonce_from_seq_channel(uint32_t seq_num, uint32_t channel_id, uint8_t *nonce) {
    memcpy(nonce, &seq_num, sizeof(uint32_t));
    memcpy(nonce + sizeof(uint32_t), &channel_id, sizeof(uint32_t));
}

bool is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL) {
        return true;
    }
    time_t now = time(NULL);
    if (now < 0) {
        now = 0;
    }
    timestamp_t current_time = (timestamp_t) now;
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

void custom_print_hex(uint8_t *data, size_t len) {
    size_t pos = 0;
    for (size_t i = 0; i < len && pos < sizeof(output_buf)-3; i++) {
        pos += sprintf(output_buf + pos, "%02x", data[i]);
    }
    output_buf[pos] = '\0';
    print_debug(output_buf);
}

void list_channels() {
    list_response_t resp = {0};
    uint32_t channel_count = 0;
    char debug_buf[64];
    sprintf(debug_buf, "Listing channels...");
    print_debug(debug_buf);

    resp.channel_info[channel_count].channel = EMERGENCY_CHANNEL;
    resp.channel_info[channel_count].start   = 0;
    resp.channel_info[channel_count].end     = 0xFFFFFFFFFFFFFFFF;
    channel_count++;

    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[channel_count].channel = decoder_status.subscribed_channels[i].id;
            resp.channel_info[channel_count].start  = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[channel_count].end    = decoder_status.subscribed_channels[i].end_timestamp;
            channel_count++;
        }
    }
    resp.n_channels = channel_count;
    write_packet(LIST_MSG, &resp, sizeof(uint32_t) + channel_count * sizeof(channel_info_t));
}

int decode(pkt_len_t frame_len, frame_packet_t *new_frame) {
    char debug_buf[64];
    print_debug("Checking subscription");

    if (!is_subscribed(new_frame->channel)) {
        STATUS_LED_RED();
        sprintf(debug_buf, "Receiving unsubscribed channel data: %u", new_frame->channel);
        print_error(debug_buf);
        return -1;
    }
    print_debug("Subscription Valid");

    encoded_frame_t *encoded_frame = (encoded_frame_t *)new_frame;
    uint8_t output_data[FRAME_SIZE + 12];
    size_t output_len = 0;

    size_t data_size = frame_len - HEADER_SIZE;
    if (data_size < 12) {
        print_error("Frame too small");
        return -1;
    }

    memcpy(output_data, encoded_frame->encrypted_data, data_size);
    output_len = data_size - 12;

    write_packet(DECODE_MSG, output_data, output_len);
    print_debug("Sent decoded frame to host");

    msg_type_t ack;
    uint16_t ack_len;
    read_packet(&ack, NULL, &ack_len);

    return 0;
}

void init() {
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        print_debug("First boot. Setting flash...");
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        channel_status_t subscription[MAX_CHANNEL_COUNT];
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp   = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }
        flash_simple_erase_page(FLASH_DEVICE_ID_ADDR);
        flash_simple_write(FLASH_DEVICE_ID_ADDR, &DEVICE_ID, sizeof(decoder_id_t));
        memcpy(decoder_status.subscribed_channels, subscription, sizeof(subscription));
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    } else {
        flash_simple_read(FLASH_KEYS_ADDR, &decoder_keys, sizeof(decoder_keys_t));
    }
    int ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        while (1);
    }
}

int main(void) {
    char     debug_buf[64];
    uint8_t  uart_buf[100];
    msg_type_t cmd;
    int      result;
    uint16_t pkt_len;
    init();
    print_debug("Decoder Booted!");
    while (1) {
        print_debug("Ready");
        STATUS_LED_GREEN();
        result = read_packet(&cmd, uart_buf, &pkt_len);
        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host");
            continue;
        }
        switch (cmd) {
            case LIST_MSG:
                STATUS_LED_CYAN();
                boot_flag();
                list_channels();
                break;
            case DECODE_MSG:
                STATUS_LED_PURPLE();
                decode(pkt_len, (frame_packet_t *)uart_buf);
                break;
            case SUBSCRIBE_MSG:
                STATUS_LED_YELLOW();
                subscription_update_packet_t *sub = (subscription_update_packet_t *)uart_buf;
                bool stored = false;
                for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
                    if (!decoder_status.subscribed_channels[i].active) {
                        decoder_status.subscribed_channels[i].id = sub->channel;
                        decoder_status.subscribed_channels[i].start_timestamp = sub->start_timestamp;
                        decoder_status.subscribed_channels[i].end_timestamp = sub->end_timestamp;
                        decoder_status.subscribed_channels[i].active = true;
                        stored = true;
                        break;
                    }
                }
                if (stored) {
                    flash_simple_erase_page(FLASH_STATUS_ADDR);
                    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
                    print_debug("Subscription stored successfully");
                    write_packet(ACK_MSG, NULL, 0);
                } else {
                    print_error("No space to store subscription");
                }
                break;
            default:
                STATUS_LED_ERROR();
                sprintf(debug_buf, "Invalid Command: %c", cmd);
                print_error(debug_buf);
                break;
        }
    }
}
