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
from Crypto.Hash import CMAC
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

# Constants
AES_BLOCK_SIZE = 16  # AES block size in bytes
KEY_SIZE = 32  # AES-256 key size in bytes
IV_SIZE = 16  # Initialization vector size
FRAME_HEADER_SIZE = 12  # Size of frame header (channel, timestamp)
MAX_FRAME_SIZE = 64  # Maximum frame payload size


def derive_key_from_master(master_key, context, salt=None):
    """
    Derive a key from the master key using AES-CMAC.

    Args:
        master_key (bytes): The master key
        context (str or bytes): Context information for key derivation
        salt (bytes, optional): Salt for additional entropy

    Returns:
        bytes: Derived key of KEY_SIZE bytes
    """
    # Ensure inputs are in bytes format
    if isinstance(master_key, bytearray):
        master_key = bytes(master_key)

    if isinstance(context, str):
        context = context.encode()
    elif isinstance(context, bytearray):
        context = bytes(context)

    if salt is None:
        salt = get_random_bytes(16)
    elif isinstance(salt, bytearray):
        salt = bytes(salt)

    # Use our aes_cmac function which handles bytearray issues
    combined_input = bytes(salt + context)
    derived_key = aes_cmac(master_key, combined_input)

    # If we need more bytes, continue with counter mode derivation
    if KEY_SIZE > len(derived_key):
        # Create a second derived block
        second_input = bytes(derived_key + context)
        second_block = aes_cmac(master_key, second_input)

        # Append the second block
        derived_key = bytes(derived_key + second_block)

    # Return the truncated or full key depending on KEY_SIZE
    return derived_key[:KEY_SIZE]


def aes_ctr_encrypt(key, plaintext, nonce=None):
    """
    Encrypt plaintext using AES-CTR mode.

    Args:
        key (bytes): Encryption key
        plaintext (bytes): Data to encrypt
        nonce (bytes, optional): Nonce for CTR mode, generated if None

    Returns:
        tuple: (ciphertext, nonce)
    """
    # Ensure inputs are in bytes format
    if isinstance(key, bytearray):
        key = bytes(key)
    if isinstance(plaintext, bytearray):
        plaintext = bytes(plaintext)

    if nonce is None:
        nonce = get_random_bytes(8)
    elif isinstance(nonce, bytearray):
        nonce = bytes(nonce)

    # Create a counter with the nonce
    ctr = Counter.new(64, prefix=nonce, initial_value=0)

    # Create cipher object and encrypt
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(plaintext)

    return ciphertext, nonce


def aes_ctr_decrypt(key, ciphertext, nonce):
    """
    Decrypt ciphertext using AES-CTR mode.

    Args:
        key (bytes): Decryption key
        ciphertext (bytes): Data to decrypt
        nonce (bytes): Nonce used for encryption

    Returns:
        bytes: Decrypted plaintext
    """
    # Ensure inputs are in bytes format
    if isinstance(key, bytearray):
        key = bytes(key)
    if isinstance(ciphertext, bytearray):
        ciphertext = bytes(ciphertext)
    if isinstance(nonce, bytearray):
        nonce = bytes(nonce)

    # Create a counter with the nonce
    ctr = Counter.new(64, prefix=nonce, initial_value=0)

    # Create cipher object and decrypt
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext


def aes_cmac(key, message):
    """
    Generate AES-CMAC for a message.

    Args:
        key (bytes): Key for CMAC
        message (bytes): Message to authenticate

    Returns:
        bytes: Authentication tag
    """
    # Ensure key and message are bytes, not bytearray
    if isinstance(key, bytearray):
        key = bytes(key)
    if isinstance(message, bytearray):
        message = bytes(message)

    try:
        # Try to process the message directly
        cmac = CMAC.new(key, ciphermod=AES)
        cmac.update(message)
        return bytes(cmac.digest())  # Convert to bytes just in case it's a bytearray
    except TypeError as e:
        # If there's a TypeError about bytearrays, try an alternative approach
        if "bytearray" in str(e):
            # Process the message in smaller chunks, converting each chunk to bytes
            cmac = CMAC.new(key, ciphermod=AES)
            chunk_size = 16  # AES block size
            for i in range(0, len(message), chunk_size):
                chunk = message[i:i + chunk_size]
                if isinstance(chunk, bytearray):
                    chunk = bytes(chunk)
                cmac.update(chunk)
            result = cmac.digest()
            if isinstance(result, bytearray):
                result = bytes(result)
            return result
        else:
            # Re-raise if it's not a bytearray issue
            raise


def verify_aes_cmac(key, message, tag):
    """
    Verify AES-CMAC for a message.

    Args:
        key (bytes): Key for CMAC
        message (bytes): Message to authenticate
        tag (bytes): Authentication tag to verify

    Returns:
        bool: True if verified, False otherwise
    """
    # Ensure all inputs are bytes, not bytearray
    if isinstance(key, bytearray):
        key = bytes(key)
    if isinstance(message, bytearray):
        message = bytes(message)
    if isinstance(tag, bytearray):
        tag = bytes(tag)

    try:
        # Try to verify directly
        cmac = CMAC.new(key, ciphermod=AES)
        cmac.update(message)
        cmac.verify(tag)
        return True
    except TypeError as e:
        # If there's a TypeError about bytearrays, try an alternative approach
        if "bytearray" in str(e):
            try:
                # Process the message in smaller chunks, converting each chunk to bytes
                cmac = CMAC.new(key, ciphermod=AES)
                chunk_size = 16  # AES block size
                for i in range(0, len(message), chunk_size):
                    chunk = message[i:i + chunk_size]
                    if isinstance(chunk, bytearray):
                        chunk = bytes(chunk)
                    cmac.update(chunk)

                # Convert tag to bytes if needed
                if isinstance(tag, bytearray):
                    tag = bytes(tag)

                cmac.verify(tag)
                return True
            except ValueError:
                return False
        else:
            # Re-raise if it's not a bytearray issue
            raise
    except ValueError:
        return False


def create_nonce_from_seq_channel(seq_num, channel_id):
    """
    Create a nonce from sequence number and channel ID.

    Args:
        seq_num (int): Sequence number
        channel_id (int): Channel ID

    Returns:
        bytes: 8-byte nonce
    """
    # Pack seq_num (4 bytes) and channel_id (4 bytes) into a 8-byte nonce
    return struct.pack("<II", seq_num, channel_id)


def bytes_to_hex(data):
    """Convert bytes to hex string for debugging"""
    # Ensure data is in bytes format
    if isinstance(data, bytearray):
        data = bytes(data)
    return binascii.hexlify(data).decode('ascii')
