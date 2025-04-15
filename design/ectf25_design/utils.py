#!/usr/bin/env python3
"""
Archivo: utils.py
Pequeñas utilidades para XOR y dumping en hex.
"""

import binascii

def bytes_to_hex(data: bytes) -> str:
    return binascii.hexlify(data).decode('ascii')

def xor_with_id(data: bytes, dev_id: int) -> bytes:
    """
    Aplica XOR de cada byte con un byte de dev_id.
    dev_id es un int de 32 bits (ej 0xDEADBEEF).
    """
    out = bytearray(len(data))
    for i in range(len(data)):
        # cada 4 bytes se repite
        shift = (i % 4) * 8
        key_byte = (dev_id >> shift) & 0xFF
        out[i] = data[i] ^ key_byte
    return bytes(out)
