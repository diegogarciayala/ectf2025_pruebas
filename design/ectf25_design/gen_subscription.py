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


def gen_subscription(
        secrets: dict,
        device_id: int,
        start: int,
        end: int,
        channel: int
) -> bytes:
    # 8 bytes dummy
    dummy = b'\x00' * 8

    # 4 + 8 + 8 + 4 = 24 bytes
    import struct
    sub_struct = struct.pack("<IQQI", device_id, start, end, channel)

    return dummy + sub_struct


def main():
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser()
    parser.add_argument("secrets_file", type=Path)
    parser.add_argument("subscription_file", type=Path)
    parser.add_argument("device_id", type=lambda x: int(x, 0))
    parser.add_argument("start", type=int)
    parser.add_argument("end", type=int)
    parser.add_argument("channel", type=int)
    parser.add_argument("-f", "--force", action="store_true")
    args = parser.parse_args()

    with open(args.secrets_file, "r") as f:
        secrets_data = json.load(f)

    subscription_data = gen_subscription(
        secrets_data,
        args.device_id,
        args.start,
        args.end,
        args.channel
    )

    mode = "wb" if args.force else "xb"
    with open(args.subscription_file, mode) as outf:
        outf.write(subscription_data)

    print(f"Suscripción escrita en {args.subscription_file} (len={len(subscription_data)})")


if __name__ == "__main__":
    main()
