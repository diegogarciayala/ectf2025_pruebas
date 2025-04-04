/**
 * @file    decoder.c
 * @author  Samuel Meyers
 * @brief   eCTF Decoder Example Design Implementation – Versión final
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"

#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#include <assert.h>
#endif  // CRYPTO_EXAMPLE

/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFFULL
#define FLASH_FIRST_BOOT 0xDEADBEEF

// Longitud fija del bloque de suscripción (tal como se genera en gen_subscription.py)
#define SUBSCRIPTION_CODE_LEN 32

// Longitud del header del paquete: (#SEQ, CH_ID, ENCODER_ID) en little-endian (3 x 4 bytes)
#define HEADER_LEN 12

// Tamaño del bloque que se cifra: FRAME (hasta 64 bytes) + TS (8 bytes) + #SEQ (4 bytes)
#define PAYLOAD_EXTRA_LEN 12

// Clave maestra hardcodeada (compartida con el encoder y gen_secrets.py)
static const uint8_t K_MASTER[] = "my_sup3r53cur3_K1_m45ter";

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1)
typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];
} frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
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
#pragma pack(pop)

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot; // Si es FLASH_FIRST_BOOT, el dispositivo ya arrancó.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

flash_entry_t decoder_status;

/**********************************************************
 ***************** CRIPTO: AES-CMAC y AES-CTR  ***************
 **********************************************************/

#ifdef CRYPTO_EXAMPLE
/*
 * Se asume que la biblioteca simple_crypto provee la siguiente función:
 * int aes_cmac(const uint8_t *key, size_t key_len,
 *              const uint8_t *data, size_t data_len,
 *              uint8_t *mac); // Escribe 16 bytes en 'mac'
 *
 * Asimismo, se asume que existe:
 * void aes_ecb_encrypt(const uint8_t *in, uint8_t *out,
 *                      const uint8_t *key, size_t key_len);
 *
 * A continuación se implementa aes_ctr_decrypt (simétrica a aes_ctr_encrypt).
 */

/* Implementa AES-CTR para descifrar 'in' de longitud 'len' usando 'key' y 'nonce'
 * nonce: 16 bytes. Se asume que el contador se encuentra en los últimos 8 bytes en big-endian.
 */
static void aes_ctr_crypt(const uint8_t *key, size_t key_len,
                          const uint8_t *nonce,
                          const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t counter_block[16];
    uint8_t keystream[16];
    size_t blocks = (len + 15) / 16;
    for (size_t i = 0; i < blocks; i++) {
        // Preparar el bloque contador: copiar nonce
        memcpy(counter_block, nonce, 16);
        // Actualizar los últimos 8 bytes (contador) en big-endian
        uint64_t ctr = 0;
        for (int j = 0; j < 8; j++) {
            ctr = (ctr << 8) | counter_block[8 + j];
        }
        ctr += i;
        for (int j = 7; j >= 0; j--) {
            counter_block[8 + j] = ctr & 0xFF;
            ctr >>= 8;
        }
        // Cifrar el bloque contador en ECB para obtener el keystream
        aes_ecb_encrypt(counter_block, keystream, key, key_len);
        // XOR del keystream con el bloque del mensaje
        size_t offset = i * 16;
        size_t block_len = ((len - offset) > 16) ? 16 : (len - offset);
        for (size_t j = 0; j < block_len; j++) {
            out[offset + j] = in[offset + j] ^ keystream[j];
        }
    }
}

/* Función wrapper para descifrar (CTR es simétrico) */
static void aes_ctr_decrypt(const uint8_t *key, size_t key_len,
                            const uint8_t *nonce,
                            const uint8_t *ciphertext, uint8_t *plaintext, size_t len) {
    aes_ctr_crypt(key, key_len, nonce, ciphertext, plaintext, len);
}
#endif  // CRYPTO_EXAMPLE

/**********************************************************
 *********************** UTILITY FUNCTIONS ****************
 **********************************************************/

int is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL)
        return 1;
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active)
            return 1;
    }
    return 0;
}

void boot_flag(void) {
    char flag[28];
    char output_buf[128] = {0};

    for (int i = 0; aseiFuengleR[i]; i++) {
        flag[i] = deobfuscate(aseiFuengleR[i], djFIehjkklIH[i]);
        flag[i + 1] = 0;
    }
    sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
    print_debug(output_buf);
}

/**********************************************************
 *********************** CORE FUNCTIONS *********************
 **********************************************************/

/**
 * Función de decodificación.
 *
 * Se asume que el paquete tiene el siguiente formato:
 *   [HEADER (12 bytes)] || [C_SUBS (SUBSCRIPTION_CODE_LEN bytes)] || [CIPHERTEXT]
 *
 * HEADER: (#SEQ, CH_ID, ENCODER_ID) en little-endian.
 *
 * El plaintext cifrado es:
 *   [FRAME (hasta 64 bytes)] || [TS (8 bytes little-endian)] || [#SEQ (4 bytes little-endian)]
 *
 * Se deriva K1 = AES-CMAC(K_MASTER, seq_div2_bytes) donde seq_div2_bytes es el valor (#SEQ // 2)
 * representado en 10 bytes big-endian.
 *
 * Se construye el nonce para AES-CTR:
 *   nonce = [#SEQ (4 bytes big-endian) || CH_ID (4 bytes big-endian) || 8 ceros]
 */
int decode(pkt_len_t pkt_len, uint8_t *packet) {
#ifdef CRYPTO_EXAMPLE
    // Verificar tamaño mínimo del paquete
    if (pkt_len < HEADER_LEN + SUBSCRIPTION_CODE_LEN + PAYLOAD_EXTRA_LEN) {
        print_error("Paquete demasiado corto\n");
        return -1;
    }

    // Extraer header (little-endian)
    uint32_t seq, channel, encoder_id;
    memcpy(&seq, packet, 4);
    memcpy(&channel, packet + 4, 4);
    memcpy(&encoder_id, packet + 8, 4);

    // Ubicar el ciphertext (después del header y del bloque de suscripción)
    uint8_t *ciphertext = packet + HEADER_LEN + SUBSCRIPTION_CODE_LEN;
    size_t ciphertext_len = pkt_len - (HEADER_LEN + SUBSCRIPTION_CODE_LEN);

    // Derivar K1:
    // Calcular seq_div2 y representarlo en 10 bytes big-endian.
    uint8_t seq_div2_bytes[10] = {0};
    uint32_t seq_div2 = seq / 2;
    for (int i = 9; i >= 0; i--) {
        seq_div2_bytes[i] = seq_div2 & 0xFF;
        seq_div2 >>= 8;
    }
    uint8_t K1[16] = {0};
    if (aes_cmac(K_MASTER, sizeof(K_MASTER) - 1, seq_div2_bytes, sizeof(seq_div2_bytes), K1) != 0) {
        print_error("Error al derivar K1\n");
        return -1;
    }

    // Construir nonce para AES-CTR:
    // nonce[0..3] = seq en big-endian, nonce[4..7] = channel en big-endian, nonce[8..15] = 0.
    uint8_t nonce[16] = {0};
    uint32_t seq_be = __builtin_bswap32(seq);
    uint32_t channel_be = __builtin_bswap32(channel);
    memcpy(nonce, &seq_be, 4);
    memcpy(nonce + 4, &channel_be, 4);
    // Los 8 bytes restantes ya son cero.

    // Descifrar el ciphertext usando AES-CTR.
    // El plaintext tendrá longitud ciphertext_len y debe contener: FRAME || TS (8 bytes) || #SEQ (4 bytes)
    uint8_t plaintext[FRAME_SIZE + PAYLOAD_EXTRA_LEN] = {0};
    if (ciphertext_len > sizeof(plaintext)) {
        print_error("Ciphertext demasiado largo\n");
        return -1;
    }
    aes_ctr_decrypt(K1, sizeof(K1), nonce, ciphertext, plaintext, ciphertext_len);

    // Calcular la longitud de FRAME
    size_t frame_len = ciphertext_len - PAYLOAD_EXTRA_LEN;
    if (frame_len > FRAME_SIZE) {
        print_error("Longitud de frame inválida\n");
        return -1;
    }

    // Extraer el frame, el timestamp y el seq del plaintext.
    uint8_t frame[FRAME_SIZE] = {0};
    memcpy(frame, plaintext, frame_len);

    timestamp_t ts = 0;
    memcpy(&ts, plaintext + frame_len, 8);  // little-endian

    uint32_t seq_check = 0;
    memcpy(&seq_check, plaintext + frame_len + 8, 4);  // little-endian

    // Verificar que el número de secuencia coincide
    if (seq_check != seq) {
        print_error("Número de secuencia no coincide\n");
        return -1;
    }

    print_debug("Paquete descifrado correctamente\n");

    // Verificar suscripción
    if (is_subscribed(channel)) {
        write_packet(DECODE_MSG, frame, frame_len);
        return 0;
    } else {
        char err_buf[64];
        sprintf(err_buf, "Canal no suscrito: %u\n", channel);
        print_error(err_buf);
        return -1;
    }
#else
    print_debug("CRYPTO_EXAMPLE no está habilitado. No se puede descifrar\n");
    return -1;
#endif  // CRYPTO_EXAMPLE
}

/**
 * Actualiza la suscripción para un canal.
 */
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    int i;

    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("No se puede suscribir al canal de emergencia\n");
        return -1;
    }

    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel ||
            !decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
            break;
        }
    }
    if (i == MAX_CHANNEL_COUNT) {
        STATUS_LED_RED();
        print_error("Máximo de suscripciones alcanzado\n");
        return -1;
    }
    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

/**
 * Lista los canales suscritos.
 */
int list_channels() {
    list_response_t resp;
    pkt_len_t len;
    resp.n_channels = 0;
    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[resp.n_channels].channel = decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }
    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);
    write_packet(LIST_MSG, &resp, len);
    return 0;
}

/**
 * Inicializa los periféricos y la memoria flash.
 */
void init() {
    int ret;
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        print_debug("Primer arranque. Configurando flash...\n");
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        channel_status_t subs[MAX_CHANNEL_COUNT];
        for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
            subs[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subs[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subs[i].active = false;
        }
        memcpy(decoder_status.subscribed_channels, subs, MAX_CHANNEL_COUNT * sizeof(channel_status_t));
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        while (1);
    }
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    uint8_t uart_buf[256];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    init();
    print_debug("Decoder iniciado!\n");

    while (1) {
        print_debug("Listo para recibir...\n");
        STATUS_LED_GREEN();
        result = read_packet(&cmd, uart_buf, &pkt_len);
        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Error al recibir comando\n");
            continue;
        }
        switch (cmd) {
            case LIST_MSG:
                STATUS_LED_CYAN();
#ifdef CRYPTO_EXAMPLE
                boot_flag();
#endif
                list_channels();
                break;
            case DECODE_MSG:
                STATUS_LED_PURPLE();
                decode(pkt_len, uart_buf);
                break;
            case SUBSCRIBE_MSG:
                STATUS_LED_YELLOW();
                update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
                break;
            default:
                STATUS_LED_ERROR();
                print_error("Comando inválido\n");
                break;
        }
    }
    return 0;
}
