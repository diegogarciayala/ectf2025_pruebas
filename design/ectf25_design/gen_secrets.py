"""
Author: TrustLab Team
Date: 2025

This source file is part of a secure satellite TV transmission system for MITRE's 2025
Embedded System CTF (eCTF). This code implements the key generation and secrets
management for the satellite TV system.
"""

import argparse
import json
import base64
import os
from pathlib import Path
from Crypto.Random import get_random_bytes

from loguru import logger
from .utils import KEY_SIZE, bytes_to_hex

def gen_secrets(channels: list[int]) -> bytes:
    master_key = get_random_bytes(KEY_SIZE)
    encoder_id = get_random_bytes(8)
    initial_seq_num = 1
    signature_key = get_random_bytes(KEY_SIZE)

    secrets = {
        "channels": channels,
        "master_key": base64.b64encode(master_key).decode('ascii'),
        "encoder_id": base64.b64encode(encoder_id).decode('ascii'),
        "initial_seq_num": initial_seq_num,
        "version": "1.0",
        "signature_key": base64.b64encode(signature_key).decode('ascii'),
    }

    logger.debug(f"Generated master key: {bytes_to_hex(master_key)}")
    logger.debug(f"Generated encoder ID: {bytes_to_hex(encoder_id)}")

    return json.dumps(secrets).encode()

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force","-f",action="store_true",help="Force creation of secrets file, overwriting existing file")
    parser.add_argument("secrets_file",type=Path,help="Path to the secrets file to be created")
    parser.add_argument("channels",nargs="+",type=int,help="Supported channels. Channel 0 is always valid")
    return parser.parse_args()

def main():
    args = parse_args()
    secrets = gen_secrets(args.channels)

    logger.debug(f"Generated secrets: {secrets}")

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)

    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")

if __name__ == "__main__":
    main()
