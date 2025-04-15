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

// ---------- Definiciones básicas ----------
#define timestamp_t         uint64_t
#define channel_id_t        uint32_t
#define decoder_id_t        uint32_t
#define pkt_len_t           uint16_t

#define MAX_CHANNEL_COUNT   8
#define EMERGENCY_CHANNEL   0  // Canal 0 => emergencias
#define FRAME_SIZE          64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT    0xDEADBEEF

// Ajusta si tu makefile/ldscript define otras direcciones:
#define FLASH_DEVICE_ID_ADDR  ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4 * MXC_FLASH_PAGE_SIZE))
#define FLASH_STATUS_ADDR     ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

// Estructuras para frames y suscripciones
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

// ---------- Variables globales ----------
flash_entry_t decoder_status;

// Si no está definido en tu Makefile, se usa 0xDEADBEEF
#ifndef DECODER_ID
#define DECODER_ID 0xDEADBEEF
#endif

decoder_id_t DEVICE_ID = DECODER_ID;

// ---------- Funciones auxiliares ----------
void print_debug(const char* s) {
    // usa tu implementación (status_led, etc.)
}

void print_error(const char* s) {
    // idem
}

// Verificar si un canal está suscrito
bool is_subscribed(channel_id_t channel) {
    // canal 0 => emergencias
    if (channel == EMERGENCY_CHANNEL) {
        return true;
    }
    time_t now = time(NULL);
    if (now < 0) {
        now = 0;
    }
    timestamp_t current_time = (timestamp_t) now;

    for(int i = 0; i < MAX_CHANNEL_COUNT; i++){
        if(decoder_status.subscribed_channels[i].active &&
           decoder_status.subscribed_channels[i].id == channel &&
           decoder_status.subscribed_channels[i].start_timestamp <= current_time &&
           decoder_status.subscribed_channels[i].end_timestamp   >= current_time) {
            return true;
        }
    }
    return false;
}

// Responder con la lista de canales
void list_channels() {
    list_response_t resp;
    memset(&resp, 0, sizeof(resp));

    // canal 0 => emergencias
    resp.channel_info[0].channel = EMERGENCY_CHANNEL;
    resp.channel_info[0].start   = 0;
    resp.channel_info[0].end     = 0xFFFFFFFFFFFFFFFF;

    uint32_t count = 1;
    for(int i=0; i<MAX_CHANNEL_COUNT; i++){
        if(decoder_status.subscribed_channels[i].active) {
            resp.channel_info[count].channel = decoder_status.subscribed_channels[i].id;
            resp.channel_info[count].start   = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[count].end     = decoder_status.subscribed_channels[i].end_timestamp;
            count++;
        }
    }
    resp.n_channels = count;

    write_packet(LIST_MSG, &resp, (pkt_len_t)(sizeof(resp.n_channels) + count * sizeof(resp.channel_info[0])));
}

// Manejar un frame entrante
int decode_frame(pkt_len_t pkt_len, const frame_packet_t *f) {
    if (!is_subscribed(f->channel)) {
        print_error("Channel not subscribed");
        return -1;
    }
    // Simple: reenvía data al host
    write_packet(DECODE_MSG, (void*)f->data, FRAME_SIZE);

    // Esperar ACK
    msg_type_t ack;
    uint16_t ack_len;
    if(read_packet(&ack, NULL, &ack_len) < 0){
        print_error("No ack from host");
        return -1;
    }
    return 0;
}

// Manejar subscripción
void handle_subscription(const uint8_t *data, pkt_len_t pkt_len) {
    // Esperamos 8 bytes dummy + 24 bytes de suscripción
    if(pkt_len < 32){
        print_error("Subscription packet too small");
        return;
    }
    // Saltar 8 bytes de dummy
    const subscription_update_packet_t* sub = (const subscription_update_packet_t*)(data + 8);

    // (Opcional) Chequear si sub->decoder_id == DEVICE_ID
    // Si tu pipeline NO lo requiere, omite esto
    // if(sub->decoder_id != DEVICE_ID){
    //     print_error("Subscription for a different device");
    //     return;
    // }

    // Buscar hueco para guardar
    for(int i=0; i<MAX_CHANNEL_COUNT; i++){
        if(!decoder_status.subscribed_channels[i].active){
            decoder_status.subscribed_channels[i].id = sub->channel;
            decoder_status.subscribed_channels[i].start_timestamp = sub->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp   = sub->end_timestamp;
            decoder_status.subscribed_channels[i].active = true;

            // Guardar en flash
            flash_simple_erase_page(FLASH_STATUS_ADDR);
            flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));

            // Enviar ACK
            write_packet(ACK_MSG, NULL, 0);
            return;
        }
    }
    print_error("No space to store subscription");
}

// Inicializar
void init_decoder() {
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));

    if(decoder_status.first_boot != FLASH_FIRST_BOOT){
        // Primer boot => resetea
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        memset(decoder_status.subscribed_channels, 0, sizeof(decoder_status.subscribed_channels));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
    }
    // Iniciar UART
    if(uart_init() < 0){
        // error handle
        while(1);
    }
}

// ---------- MAIN LOOP ----------
int main(void) {
    init_decoder();

    uint8_t rx_buf[128];
    msg_type_t cmd;
    uint16_t pkt_len;

    while(1){
        if(read_packet(&cmd, rx_buf, &pkt_len) <0){
            print_error("Failed to read packet from host");
            continue;
        }
        switch(cmd){
            case LIST_MSG:
                list_channels();
                break;
            case DECODE_MSG:
                decode_frame(pkt_len, (frame_packet_t*)rx_buf);
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
