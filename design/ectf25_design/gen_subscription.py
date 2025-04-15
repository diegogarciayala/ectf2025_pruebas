#!/usr/bin/env python3
"""
Archivo: gen_subscription.py
Produce una suscripción muy simple:
 - 8 bytes dummy (para el offset)
 - 4 bytes device_id
 - 8 bytes start
 - 8 bytes end
 - 4 bytes channel
"""

import argparse
import json
import struct
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("secrets_file", type=Path, help="JSON con {decoder_id, channels}")
    parser.add_argument("subscription_file", type=Path, help="Salida binaria .bin")
    parser.add_argument("device_id", type=lambda x: int(x,0), help="ID del decodificador en hex, ej 0xDEADBEEF")
    parser.add_argument("start", type=int, help="start timestamp (64 bits)")
    parser.add_argument("end", type=int, help="end timestamp (64 bits)")
    parser.add_argument("channel", type=int, help="canal a suscribir")
    parser.add_argument("-f","--force",action="store_true",help="Fuerza sobreescritura")
    args = parser.parse_args()

    with open(args.secrets_file, "r") as f:
        secrets_json = json.load(f)

    # 8 bytes dummy
    dummy = b'\x00'*8

    # 4 + 8 + 8 + 4 = 24 bytes
    sub_struct = struct.pack("<IQQI", args.device_id, args.start, args.end, args.channel)

    full_data = dummy + sub_struct

    mode = "wb" if args.force else "xb"
    with open(args.subscription_file, mode) as outf:
        outf.write(full_data)

    print(f"Suscripción escrita en {args.subscription_file} (32 bytes)")

if __name__ == "__main__":
    main()
