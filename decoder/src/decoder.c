/**
 * @file    decoder.c
 * @author  TrustLab Team
 * @brief   eCTF Secure Satellite TV Decoder Implementation
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
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"

/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the project.mk file. */
#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"

// Forward declarations for crypto functions
extern int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);
extern int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);
extern int hash(void *data, size_t len, uint8_t *hash_out);
#endif

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
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

// Cryptography constants
#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32
#define CMAC_SIZE 16
#define ENCODER_ID_SIZE 8
#define NONCE_SIZE 8
#define HEADER_SIZE 12  // 4-byte seq_num + 4-byte channel + 4-byte encoder_id
#define FLASH_DEVICE_ID_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (4 * MXC_FLASH_PAGE_SIZE))

// Flash storage
// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
// Calculate the flash address where master keys are stored
#define FLASH_KEYS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (3 * MXC_FLASH_PAGE_SIZE))

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html
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

// Custom frame structures for our implementation
typedef struct {
    uint32_t seq_num;         // Sequence number for this frame
    uint32_t channel;         // Channel ID
    uint8_t encoder_id[8];    // Encoder ID (8 bytes)
    uint8_t encrypted_data[]; // Variable length encrypted data
} encoded_frame_t;

// Structure for master keys stored in flash
typedef struct {
    uint8_t master_key[KEY_SIZE];
    uint8_t signature_key[KEY_SIZE];
    uint8_t encoder_id[ENCODER_ID_SIZE];
} decoder_keys_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

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
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;

// Track last sequence number to prevent replay attacks
uint32_t last_seq_num = 0;

// Master keys and encoder ID
decoder_keys_t decoder_keys;

// Derived keys for each channel
uint8_t channel_keys[MAX_CHANNEL_COUNT][KEY_SIZE];

// Buffer for debug output
char output_buf[128];

#ifndef DECODER_ID
#define DECODER_ID 0xDEADBEEF
#endif

decoder_id_t DEVICE_ID = DECODER_ID;

/**********************************************************
 ******************** REFERENCE FLAG **********************
 **********************************************************/

/* DO NOT MODIFY THIS FUNCTION! This is the 'flag' code that
 * the automated grader is looking for. This function should
 * be called from your main */
void boot_flag() {
    // If the program calls this function, the flag will be read and printed
    char flag_buf[64];
    sprintf(flag_buf, "boot flag: %p", boot_flag);
    print_debug(flag_buf);
}

/**********************************************************
 ***************** CRYPTO HELPER FUNCTIONS ****************
 **********************************************************/

/**
 * @brief Create a nonce from sequence number and channel ID
 *
 * @param seq_num Sequence number
 * @param channel_id Channel ID
 * @param nonce Output buffer for nonce (8 bytes)
 */
void create_nonce_from_seq_channel(uint32_t seq_num, uint32_t channel_id, uint8_t *nonce) {
    // Pack seq_num (4 bytes) and channel_id (4 bytes) into a 8-byte nonce
    memcpy(nonce, &seq_num, sizeof(uint32_t));
    memcpy(nonce + sizeof(uint32_t), &channel_id, sizeof(uint32_t));
}

#ifdef CRYPTO_EXAMPLE
/**
 * @brief Implement AES-CTR encryption/decryption
 *
 * @param key The encryption/decryption key
 * @param in Input data
 * @param len Length of input data
 * @param nonce The nonce for CTR mode
 * @param out Output buffer for results
 * @return int 0 on success, error code otherwise
 */
int aes_ctr_crypt(uint8_t *key, uint8_t *in, size_t len, uint8_t *nonce, uint8_t *out) {
    // For this implementation, we'll use ECB mode to simulate CTR
    // This is a simplified version for the CTF context

    // Create a counter block
    uint8_t counter_block[AES_BLOCK_SIZE];
    uint8_t encrypted_counter[AES_BLOCK_SIZE];
    uint32_t counter = 0;
    int result;

    // For each block
    for (size_t i = 0; i < len; i += AES_BLOCK_SIZE) {
        // Create the counter block = nonce + counter
        memcpy(counter_block, nonce, NONCE_SIZE);
        memcpy(counter_block + NONCE_SIZE, &counter, sizeof(counter));
        counter++;

        // Encrypt the counter
        result = encrypt_sym(counter_block, AES_BLOCK_SIZE, key, encrypted_counter);
        if (result != 0) {
            return result;
        }

        // XOR the input with the encrypted counter
        for (size_t j = 0; j < AES_BLOCK_SIZE && (i + j) < len; j++) {
            out[i + j] = in[i + j] ^ encrypted_counter[j];
        }
    }

    return 0;
}

/**
 * @brief Implement AES-CMAC for message authentication
 *
 * @param key The key used for CMAC
 * @param message The message to authenticate
 * @param len Length of the message
 * @param mac Output buffer for the CMAC value (16 bytes)
 * @return int 0 on success, error code otherwise
 */
int aes_cmac(uint8_t *key, uint8_t *message, size_t len, uint8_t *mac) {
    // Simplified CMAC implementation for CTF
    // In a real-world scenario, use a proper CMAC implementation

    // For simplicity, we're using AES in ECB mode and padding
    uint8_t padded_message[AES_BLOCK_SIZE * ((len / AES_BLOCK_SIZE) + 1)];
    memset(padded_message, 0, sizeof(padded_message));
    memcpy(padded_message, message, len);

    // Add padding
    padded_message[len] = 0x80;  // 1 followed by zeros

    // Encrypt the last block to generate the MAC
    size_t padded_len = ((len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    return encrypt_sym(padded_message + padded_len - AES_BLOCK_SIZE,
                      AES_BLOCK_SIZE, key, mac);
}

/**
 * @brief Verify a CMAC value against a message
 *
 * @param key The key used for CMAC
 * @param message The message to verify
 * @param len Length of the message
 * @param mac The CMAC value to verify against
 * @return int 1 if verified, 0 if not verified, negative on error
 */
int verify_aes_cmac(uint8_t *key, uint8_t *message, size_t len, uint8_t *mac) {
    uint8_t calculated_mac[CMAC_SIZE];
    int result = aes_cmac(key, message, len, calculated_mac);

    if (result != 0) {
        return result;
    }

    // Compare the MACs
    if (memcmp(calculated_mac, mac, CMAC_SIZE) == 0) {
        return 1;  // Verified
    } else {
        return 0;  // Not verified
    }
}

/**
 * @brief Derive a key from the master key using AES-CMAC
 *
 * @param master_key The master key
 * @param context Context string for key derivation
 * @param salt Optional salt for additional entropy (can be NULL)
 * @param derived_key Output buffer for the derived key
 * @return int 0 on success, error code otherwise
 */
int derive_key_from_master(uint8_t *master_key, const char *context,
                          uint8_t *salt, uint8_t *derived_key) {
    // Create a context message: salt + context string
    uint8_t context_message[64];
    size_t context_len = 0;

    if (salt != NULL) {
        memcpy(context_message, salt, 16);
        context_len += 16;
    }

    size_t context_str_len = strlen(context);
    memcpy(context_message + context_len, context, context_str_len);
    context_len += context_str_len;

    // First 16 bytes - use CMAC directly
    int result = aes_cmac(master_key, context_message, context_len, derived_key);
    if (result != 0) {
        return result;
    }

    // For the second 16 bytes, modify the context slightly
    context_message[context_len] = 0x01;
    return aes_cmac(master_key, context_message, context_len + 1, derived_key + CMAC_SIZE);
}
#endif

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

// This function checks if the decoder is currently subscribed to a channel
// by looping through the active channel subscriptions
bool is_subscribed(channel_id_t channel) {
    // Emergency channel is always subscribed
    if (channel == EMERGENCY_CHANNEL) {
        return true;
    }

    timestamp_t current_time = 0;  // In a real system this would be a real timestamp

    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active &&
            decoder_status.subscribed_channels[i].id == channel &&
            decoder_status.subscribed_channels[i].start_timestamp <= current_time &&
            decoder_status.subscribed_channels[i].end_timestamp >= current_time) {
            return true;
        }
    }
    return false;
}

int find_free_channel_slot() {
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (!decoder_status.subscribed_channels[i].active) {
            return i;
        }
    }
    // No free slots
    return -1;
}

// Custom function for printing hex data in debug
void custom_print_hex(uint8_t *data, size_t len) {
    size_t pos = 0;

    for (size_t i = 0; i < len && pos < sizeof(output_buf)-3; i++) {
        pos += sprintf(output_buf + pos, "%02x", data[i]);
    }

    output_buf[pos] = '\0';
    print_debug(output_buf);
}

// This function lists the active channel subscriptions
void list_channels() {
    list_response_t resp = {0};
    uint32_t channel_count = 0;
    char debug_buf[64];

    sprintf(debug_buf, "Listing channels...");
    print_debug(debug_buf);

    // First channel is always the emergency broadcast
    resp.channel_info[channel_count].channel = EMERGENCY_CHANNEL;
    resp.channel_info[channel_count].start = 0;
    resp.channel_info[channel_count].end = 0xFFFFFFFFFFFFFFFF;
    channel_count++;

    // Add any other subscribed channels
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[channel_count].channel = decoder_status.subscribed_channels[i].id;
            resp.channel_info[channel_count].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[channel_count].end = decoder_status.subscribed_channels[i].end_timestamp;
            channel_count++;
        }
    }

    // Set the total number of channels
    resp.n_channels = channel_count;

    // Send the channel list back to the host
    write_packet(LIST_MSG, &resp, sizeof(uint32_t) + channel_count * sizeof(channel_info_t));
}

/**********************************************************
 ******************* COMMAND FUNCTIONS ********************
 **********************************************************/

int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *sub_data){
    // Realmente 'sub_data' apunta al inicio del buffer completo (encoder_id + suscripción + firma).
    // Así que creamos un puntero a raw bytes:
    uint8_t *raw_buf = (uint8_t *) sub_data;

    // 1) Leer 8 bytes de encoder_id (no usados)
    uint8_t encoder_id[8];
    memcpy(encoder_id, raw_buf, 8);

    // 2) La suscripción de 24 bytes está en offset 8
    subscription_update_packet_t *sub_ptr =
        (subscription_update_packet_t *)(raw_buf + 8);

    // 3) La firma (16 bytes) está en offset 8 + 24 = 32
    size_t sub_len = 8 + sizeof(subscription_update_packet_t); // = 32
    uint8_t *signature = raw_buf + sub_len; // offset 32

#ifdef CRYPTO_EXAMPLE
    // 4) Verificar la firma

    // El bloque a firmar son estos 8 bytes + los 24 bytes de la suscripción (en total 32).
    size_t subscription_data_len = 8 + sizeof(subscription_update_packet_t); // = 8 + 24 = 32
    if (pkt_len < subscription_data_len + CMAC_SIZE) {
        print_error("Invalid subscription packet length");
        return -1;
    }

    // La firma son los últimos 16 bytes
    uint8_t *signature = raw_buf + subscription_data_len;

    // Confirmar la firma sobre los primeros 32 bytes (encoder_id + suscripción)
    if (verify_aes_cmac(decoder_keys.signature_key,
                        raw_buf,                  // buffer completo
                        subscription_data_len,    // 32
                        signature) != 1) {
        print_error("Invalid subscription signature");
        return -1;
    }
#endif

    // 5) Buscar slot libre
    int slot = find_free_channel_slot();
    if (slot < 0) {
        print_error("No free subscription slots");
        return -1;
    }

    // 6) Actualizar la suscripción en memoria
    decoder_status.subscribed_channels[slot].active = true;
    decoder_status.subscribed_channels[slot].id = real_sub_data->channel;
    decoder_status.subscribed_channels[slot].start_timestamp = real_sub_data->start_timestamp;
    decoder_status.subscribed_channels[slot].end_timestamp   = real_sub_data->end_timestamp;

    // 7) Guardar en flash
    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    print_debug("Subscription updated and saved");

#ifdef CRYPTO_EXAMPLE
    // 8) Derivar la clave de canal (excepto canal de emergencia)
    if (real_sub_data->channel != EMERGENCY_CHANNEL) {
        char context[20];
        sprintf(context, "channel-%u", real_sub_data->channel);
        derive_key_from_master(decoder_keys.master_key, context, NULL,
                               channel_keys[real_sub_data->channel]);

        print_debug("Channel key derived");
        sprintf(debug_buf, "Key: ");
        print_debug(debug_buf);
        custom_print_hex(channel_keys[real_sub_data->channel], 16);
    }
#endif

    return 0;
}


// This function is called when the decoder receives a frame to decode
int decode(pkt_len_t frame_len, frame_packet_t *new_frame) {
    char debug_buf[64];
    uint8_t decrypted_data[FRAME_SIZE + 12]; // Frame + timestamp + seq_num
    int result;

    // Get channel ID from the frame
    channel_id_t channel = new_frame->channel;

    sprintf(debug_buf, "Decoding frame for channel %u", channel);
    print_debug(debug_buf);

    // Check that we are subscribed to the channel
    print_debug("Checking subscription");
    if (!is_subscribed(channel)) {
        STATUS_LED_RED();
        sprintf(debug_buf, "Receiving unsubscribed channel data: %u", channel);
        print_error(debug_buf);
        return -1;
    }

    print_debug("Subscription Valid");

#ifdef CRYPTO_EXAMPLE
    // Cast to our custom frame structure for easier access
    encoded_frame_t *encoded_frame = (encoded_frame_t *)new_frame;

    // Check sequence number to prevent replay attacks
    if (encoded_frame->seq_num <= last_seq_num && last_seq_num > 0) {
        print_error("Possible replay attack detected");
        return -1;
    }

    // Update sequence number
    last_seq_num = encoded_frame->seq_num;

    // Verify that encoder ID matches
    if (memcmp(encoded_frame->encoder_id, decoder_keys.encoder_id, ENCODER_ID_SIZE) != 0) {
        print_error("Invalid encoder ID");
        return -1;
    }

    // Get key for this channel (emergency channel uses master key directly)
    uint8_t *key = (channel == EMERGENCY_CHANNEL) ?
                  decoder_keys.master_key : channel_keys[channel];

    // Create nonce from sequence number and channel
    uint8_t nonce[NONCE_SIZE];
    create_nonce_from_seq_channel(encoded_frame->seq_num, channel, nonce);

    // Calculate size of encrypted data
    size_t encrypted_data_size = frame_len - HEADER_SIZE;

    // Decrypt the frame data
    result = aes_ctr_crypt(key, encoded_frame->encrypted_data,
                          encrypted_data_size, nonce, decrypted_data);

    if (result != 0) {
        sprintf(debug_buf, "Decryption failed with error %d", result);
        print_error(debug_buf);
        return -1;
    }

    // Extract the timestamp and verify it's current
    timestamp_t timestamp;
    uint32_t seq_num_check;
    memcpy(&timestamp, decrypted_data + encrypted_data_size - 12, sizeof(timestamp_t));
    memcpy(&seq_num_check, decrypted_data + encrypted_data_size - 4, sizeof(uint32_t));

    // Verify sequence number in encrypted data matches header
    if (seq_num_check != encoded_frame->seq_num) {
        print_error("Sequence number mismatch");
        return -1;
    }

    // Copy just the frame data (without timestamp and seq_num) to the output
    memcpy(new_frame->data, decrypted_data, encrypted_data_size - 12);
#endif

    // Send the decrypted data back to the host
    write_packet(DECODE_MSG, new_frame->data, frame_len > 12 ? frame_len - 12 : 0);
    return 0;
}

/** @brief Initializes peripherals for system boot.
*/
void init() {
    int ret;

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        print_debug("First boot. Setting flash...");

        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }

				// Save the DEVICE_ID into flash during first boot
				flash_simple_erase_page(FLASH_DEVICE_ID_ADDR);
				flash_simple_write(FLASH_DEVICE_ID_ADDR, &DEVICE_ID, sizeof(decoder_id_t));

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));

#ifdef CRYPTO_EXAMPLE
        // Initialize decoder keys
        // In a real system, these would be securely provisioned
        // For this CTF, we'll use hardcoded values for testing
        memset(decoder_keys.master_key, 0x42, KEY_SIZE);
        memset(decoder_keys.signature_key, 0x43, KEY_SIZE);
        memset(decoder_keys.encoder_id, 0x44, ENCODER_ID_SIZE);

        // Save keys to flash
        flash_simple_erase_page(FLASH_KEYS_ADDR);
        flash_simple_write(FLASH_KEYS_ADDR, &decoder_keys, sizeof(decoder_keys_t));
#endif
    } else {
        // Read stored keys from flash
        flash_simple_read(FLASH_KEYS_ADDR, &decoder_keys, sizeof(decoder_keys_t));
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
}

#ifdef CRYPTO_EXAMPLE
/**
 * This function provides a basic example of how the crypto API should be used.
 */
void crypto_example() {
    uint8_t key[KEY_SIZE] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };
    uint8_t ciphertext[AES_BLOCK_SIZE] = {0};
    uint8_t decrypted[AES_BLOCK_SIZE + 1] = {0};
    uint8_t hash_out[HASH_SIZE] = {0};
    char data[AES_BLOCK_SIZE] = "Hello eCTF 2025";
    char debug_buf[64];

    print_debug("============== CRYPTO EXAMPLE ==============");
    sprintf(debug_buf, "Original data: %s", data);
    print_debug(debug_buf);

    // Encrypt example data and print out
    encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext);
    print_debug("Encrypted data: ");
    custom_print_hex(ciphertext, BLOCK_SIZE);

    // Hash example encryption results
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: ");
    custom_print_hex(hash_out, HASH_SIZE);

    // Decrypt the encrypted message and print out
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    sprintf(debug_buf, "Decrypted message: %s", decrypted);
    print_debug(debug_buf);
}
#endif  //CRYPTO_EXAMPLE

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char debug_buf[64];
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    print_debug("Decoder Booted!");

    // process commands forever
    while (1) {
        print_debug("Ready");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host");
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();

            #ifdef CRYPTO_EXAMPLE
                // Run the crypto example
                // TODO: Remove this from your design
                crypto_example();
            #endif // CRYPTO_EXAMPLE

            // Print the boot flag
            // TODO: Remove this from your design
            boot_flag();
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, uart_buf); // pasamos el buffer crudo
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            sprintf(debug_buf, "Invalid Command: %c", cmd);
            print_error(debug_buf);
            break;
        }
    }
}