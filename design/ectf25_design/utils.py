"""
Author: TrustLab Team
Date: 2025

This source file is part of a secure satellite TV transmission system for MITRE's 2025
Embedded System CTF (eCTF). This file contains utility functions used by encoder,
gen_secrets, and gen_subscription components.

Copyright: Copyright (c) 2025
"""

import os
import json
import binascii
import struct
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

AES_BLOCK_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
FRAME_HEADER_SIZE = 12
MAX_FRAME_SIZE = 64

def bytes_to_hex(data):
    if isinstance(data, bytearray):
        data = bytes(data)
    return binascii.hexlify(data).decode('ascii')

def aes_ctr_encrypt(key, plaintext, nonce=None):
    if isinstance(key, bytearray):
        key = bytes(key)
    if isinstance(plaintext, bytearray):
        plaintext = bytes(plaintext)

    if nonce is None:
        nonce = get_random_bytes(8)
    elif isinstance(nonce, bytearray):
        nonce = bytes(nonce)

    ctr = Counter.new(64, prefix=nonce, initial_value=0)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, nonce

def aes_ctr_decrypt(key, ciphertext, nonce):
    if isinstance(key, bytearray):
        key = bytes(key)
    if isinstance(ciphertext, bytearray):
        ciphertext = bytes(ciphertext)
    if isinstance(nonce, bytearray):
        nonce = bytes(nonce)

    ctr = Counter.new(64, prefix=nonce, initial_value=0)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def create_nonce_from_seq_channel(seq_num, channel_id):
    # 4 bytes de seq_num + 4 bytes de channel_id
    return struct.pack("<II", seq_num, channel_id)

def aes_cmac(key, message):
    """
    'Simplified CMAC' that matches the firmware's approach in decoder.c:
      1) Pad (0x80 + zeros) to a multiple of 16.
      2) AES-ECB encrypt the *last block* to generate the MAC (16 bytes).
    """
    if isinstance(key, bytearray):
        key = bytes(key)
    if isinstance(message, bytearray):
        message = bytes(message)

    BLOCK_SIZE = 16
    length = len(message)
    remainder = length % BLOCK_SIZE
    padded = bytearray(message)

    if remainder == 0:
        # ya es múltiplo de 16 => agregamos un nuevo bloque
        padded.extend([0x80] + [0]*(BLOCK_SIZE-1))
    else:
        # añadimos 0x80 + ceros en la parte final
        needed = (BLOCK_SIZE - remainder)
        padded.extend([0x80] + [0]*(needed-1))

    # extraer el último bloque de 16 bytes
    last_block = padded[-BLOCK_SIZE:]

    # AES-ECB para encriptar la última base
    cipher = AES.new(key, AES.MODE_ECB)
    mac = cipher.encrypt(bytes(last_block))

    return mac

def verify_aes_cmac(key, message, tag):
    computed = aes_cmac(key, message)
    if len(computed) != len(tag):
        return 0
    # time-constant compare
    diff = 0
    for a, b in zip(computed, tag):
        diff |= (a ^ b)
    return 1 if diff == 0 else 0

def derive_key_from_master(master_key, context, salt=None):
    """
    Replica de la función en decoder.c:

      int derive_key_from_master(uint8_t *master_key, const char *context,
                                uint8_t *salt, uint8_t *derived_key)

    1) context_message = salt (16B) + context
    2) aes_cmac(master_key, context_message) -> derived_key[0..15]
    3) context_message += 0x01
    4) aes_cmac(...) -> derived_key[16..31]
    """
    if isinstance(master_key, bytearray):
        master_key = bytes(master_key)
    if isinstance(context, str):
        context = context.encode('utf-8')
    if salt is not None and isinstance(salt, bytearray):
        salt = bytes(salt)

    # Construimos context_message
    context_message = bytearray()
    if salt:
        if len(salt) != 16:
            raise ValueError("Salt must be 16 bytes if provided")
        context_message.extend(salt)

    context_message.extend(context)

    # derived key => 32 bytes
    derived_key = bytearray(32)

    # cmac1 => first 16 bytes
    cmac1 = aes_cmac(master_key, context_message)
    derived_key[0:16] = cmac1

    # cmac2 => second 16 bytes
    context_message.append(0x01)
    cmac2 = aes_cmac(master_key, context_message)
    derived_key[16:32] = cmac2

    return bytes(derived_key)
