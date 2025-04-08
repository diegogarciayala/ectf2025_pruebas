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
    return struct.pack("<II", seq_num, channel_id)

def aes_cmac(key, message):
    """
    Replicate the 'Simplified CMAC' from firmware:
      1) pad with 0x80 + zeroes to multiple of 16
      2) AES-ECB encrypt the last 16 bytes -> MAC
    """
    if isinstance(key, bytearray):
        key = bytes(key)
    if isinstance(message, bytearray):
        message = bytes(message)

    # 1) padding
    BLOCK_SIZE = 16
    length = len(message)
    remainder = length % BLOCK_SIZE

    padded_len = length
    if remainder != 0:
        padded_len += (BLOCK_SIZE - remainder)
    padded = bytearray(padded_len)
    padded[:length] = message
    # add 0x80 at offset "length"
    if remainder == 0:
        # if it's already multiple of 16, we still add a new block with 0x80
        padded += bytearray([0x80] + [0]*(BLOCK_SIZE-1))
    else:
        padded[length] = 0x80

    # now the last block is the final 16 bytes
    # (the firmware specifically encrypts only the last block as the MAC)
    # but let's clarify the firmware code: it does "encrypt_sym(padded_last_block)"
    # we do the same with AES-ECB
    # Actually the firmware's code also is "padded_len = block count * 16"
    # let's replicate exactly:

    # recalc final length
    final_len = len(padded)
    last_block = padded[final_len - BLOCK_SIZE: final_len]

    cipher = AES.new(key, AES.MODE_ECB)
    mac = cipher.encrypt(bytes(last_block))

    return mac

def verify_aes_cmac(key, message, tag):
    # Volvemos a generar el CMAC y comparamos
    computed = aes_cmac(key, message)
    if len(computed) != len(tag):
        return 0
    # time-constant compare
    diff = 0
    for a, b in zip(computed, tag):
        diff |= (a ^ b)
    return 1 if (diff == 0) else 0
