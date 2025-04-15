#!/usr/bin/env python3
"""
Archivo: encoder.py
Aplica XOR con device_id para encriptar frames.
Si channel=0 => no XOR.
"""

import argparse
import struct
import json
from pathlib import Path

from .utils import xor_with_id, bytes_to_hex

class Encoder:
    def __init__(self, secrets_json: dict):
        self.decoder_id = secrets_json["decoder_id"]
        # canal 0 es emergencias => sin XOR
        self.valid_channels = secrets_json["channels"]

    def encode(self, channel: int, frame_data: bytes, timestamp: int) -> bytes:
        """
        Retorna:
        4 bytes channel + 8 bytes timestamp + 64 bytes data (XOR si canal !=0).
        """
        if channel not in self.valid_channels:
            raise ValueError(f"Canal {channel} no es válido en secrets")

        if len(frame_data) != 64:
            raise ValueError("Frame debe tener exactamente 64 bytes")

        packed_header = struct.pack("<IQ", channel, timestamp)
        if channel == 0:
            encrypted_data = frame_data
        else:
            encrypted_data = xor_with_id(frame_data, self.decoder_id)

        return packed_header + encrypted_data

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("secrets_file", type=Path, help="JSON con {decoder_id, channels}")
    parser.add_argument("channel", type=int)
    parser.add_argument("frame", help="texto del frame (64 chars)")
    parser.add_argument("timestamp", type=int, help="timestamp 64b")
    args = parser.parse_args()

    with open(args.secrets_file, "r") as f:
        secrets_json = json.load(f)

    enc = Encoder(secrets_json)
    # forzamos que la data sea 64 bytes
    frame_data = args.frame.encode('utf-8')
    frame_data = frame_data[:64].ljust(64, b'_')  # relleno con '_'

    encoded = enc.encode(args.channel, frame_data, args.timestamp)
    print(f"Encoded: {bytes_to_hex(encoded)}")
    print(f"Len: {len(encoded)} bytes")

if __name__ == "__main__":
    main()
