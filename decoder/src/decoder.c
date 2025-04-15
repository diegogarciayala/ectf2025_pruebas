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

// ========== Definiciones y tipos básicos ==========
#define timestamp_t         uint64_t
#define channel_id_t        uint32_t
#define decoder_id_t        uint32_t
#define pkt_len_t           uint16_t

#define MAX_CHANNEL_COUNT   8
#define EMERGENCY_CHANNEL   0   // Canal de emergencias
#define FRAME_SIZE          64
#define DEFAULT_CHANNEL_TIMESTAMP  0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT    0xDEADBEEF

// Ajustar según tu plataforma/ldscript:
#define FLASH_DEVICE_ID_ADDR  ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4 * MXC_FLASH_PAGE_SIZE))
#define FLASH_STATUS_ADDR     ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

#pragma pack(push,1)
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
    bool         active;
    channel_id_t id;
    timestamp_t  start_timestamp;
    timestamp_t  end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot;
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

typedef struct {
    uint32_t n_channels;
    struct {
        channel_id_t channel;
        timestamp_t  start;
        timestamp_t  end;
    } channel_info[MAX_CHANNEL_COUNT];
} list_response_t;
#pragma pack(pop)

// ========== Variables Globales ==========
flash_entry_t decoder_status;

#ifndef DECODER_ID
#define DECODER_ID 0xDEADBEEF
#endif
decoder_id_t DEVICE_ID = DECODER_ID;

// ========== Funciones auxiliares ==========

// Chequea si un canal está suscrito
bool is_subscribed(channel_id_t channel)
{
    // Canal 0 => emergencias
    if (channel == EMERGENCY_CHANNEL) {
        return true;
    }

    time_t now = time(NULL);
    if (now < 0) {
        now = 0;
    }
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

// Envía la lista de canales a host (LIST_MSG)
void list_channels(void)
{
    list_response_t resp;
    memset(&resp, 0, sizeof(resp));

    // Canal 0 => emergencias
    resp.channel_info[0].channel = EMERGENCY_CHANNEL;
    resp.channel_info[0].start   = 0;
    resp.channel_info[0].end     = 0xFFFFFFFFFFFFFFFF;

    uint32_t count = 1;
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[count].channel = decoder_status.subscribed_channels[i].id;
            resp.channel_info[count].start   = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[count].end     = decoder_status.subscribed_channels[i].end_timestamp;
            count++;
        }
    }
    resp.n_channels = count;

    print_debug("Listing channels");
    write_packet(LIST_MSG, &resp,
        (pkt_len_t)(sizeof(resp.n_channels) + count * sizeof(resp.channel_info[0])));
}

// Decodifica (aquí, sin cifrado) y reenvía el frame
int decode_frame(pkt_len_t pkt_len, const frame_packet_t *f)
{
    // Chequear si canal está suscrito
    if (!is_subscribed(f->channel)) {
        print_error("Channel not subscribed");
        return -1;
    }
    print_debug("Channel OK -> decoding frame");

    // Reenvía la data al host
    write_packet(DECODE_MSG, (void *)f->data, FRAME_SIZE);

    // Esperamos ACK
    msg_type_t ack_type;
    uint16_t ack_len;
    if (read_packet(&ack_type, NULL, &ack_len) < 0) {
        print_error("No ACK from host after decode");
        return -1;
    }

    return 0;
}

// Maneja suscripción (SUBSCRIBE_MSG)
void handle_subscription(const uint8_t *data, pkt_len_t pkt_len)
{
    // Formato => 8 bytes dummy + 24 bytes sub
    if (pkt_len < 32) {
        print_error("Subscription packet too small");
        return;
    }

    // Saltar 8 bytes dummy
    const subscription_update_packet_t *sub = (const subscription_update_packet_t *)(data + 8);

    // (Opcional) Chequear que sub->decoder_id == DEVICE_ID
    // if (sub->decoder_id != DEVICE_ID) {
    //     print_error("Subscription for another device ID");
    //     return;
    // }

    // Buscar ranura libre
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (!decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].id = sub->channel;
            decoder_status.subscribed_channels[i].start_timestamp = sub->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp   = sub->end_timestamp;
            decoder_status.subscribed_channels[i].active = true;

            // Guardar en flash
            flash_simple_erase_page(FLASH_STATUS_ADDR);
            flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));

            print_debug("Subscription stored");
            // Responder con ACK
            write_packet(ACK_MSG, NULL, 0);
            return;
        }
    }
    print_error("No space for new subscription");
}

// Inicializa el decoder
void init_decoder(void)
{
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        print_debug("First boot => clearing subscription status");
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        memset(decoder_status.subscribed_channels, 0, sizeof(decoder_status.subscribed_channels));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
    }

    if (uart_init() < 0) {
        print_error("UART init failed");
        while (1) {
            // freeze
        }
    }
}

// ========== MAIN LOOP ==========
int main(void)
{
    init_decoder();

    uint8_t rx_buf[128];
    msg_type_t cmd;
    uint16_t pkt_len;

    print_debug("Decoder Booted!");

    while (true) {
        // Esperamos comando
        if (read_packet(&cmd, rx_buf, &pkt_len) < 0) {
            print_error("Failed to read packet");
            continue;
        }
        switch (cmd) {
            case LIST_MSG:
                list_channels();
                break;
            case DECODE_MSG:
                decode_frame(pkt_len, (const frame_packet_t *)rx_buf);
                break;
            case SUBSCRIBE_MSG:
                handle_subscription(rx_buf, pkt_len);
                break;
            default:
                print_error("Unknown command");
                break;
        }
    }

    return 0;
}
