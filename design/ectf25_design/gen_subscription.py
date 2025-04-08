"""
Author: TrustLab Team
Date: 2025

This source file is part of a secure satellite TV transmission system for MITRE's 2025
Embedded System CTF (eCTF). This code implements subscription generation for the
satellite TV system.
"""

import argparse
import json
import base64
import struct
import time
from pathlib import Path

from loguru import logger
from .utils import aes_cmac, bytes_to_hex

ONE_MONTH_SECONDS = 2592000  # 30 días ~ 2592000s

def gen_subscription(
    secrets: bytes, device_id: int, _cli_start: int, _cli_end: int, channel: int
) -> bytes:
    """
    The output will be passed to the Decoder.
    We IGNORE the CLI start/end, so that the subscription is valid from 'now' to 'now + 30d'.
    """
    secrets_json = json.loads(secrets)
    master_key = base64.b64decode(secrets_json["master_key"])
    encoder_id = base64.b64decode(secrets_json["encoder_id"])
    signature_key = base64.b64decode(secrets_json["signature_key"])

    if channel != 0 and channel not in secrets_json["channels"]:
        raise ValueError(f"Channel {channel} is not valid in this deployment")

    # Forzamos 'start' y 'end'
    start = int(time.time())
    end   = start + ONE_MONTH_SECONDS

    # subscription_data: 4B device_id + 8B start + 8B end + 4B channel = 24 bytes
    subscription_data = struct.pack("<IQQI", device_id, start, end, channel)

    # 8 bytes encoder_id + 24 bytes subscription
    subscription_with_id = encoder_id + subscription_data

    signature = aes_cmac(signature_key, subscription_with_id)
    complete_subscription = subscription_with_id + signature

    logger.debug(f"Subscription data: device_id={device_id}, start={start}, end={end}, channel={channel}")
    logger.debug(f"Encoder ID: {bytes_to_hex(encoder_id)}")
    logger.debug(f"Signature: {bytes_to_hex(signature)}")

    return complete_subscription

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force","-f",action="store_true",help="Force creation of subscription file")
    parser.add_argument("secrets_file",type=argparse.FileType("rb"),help="Path to the secrets file")
    parser.add_argument("subscription_file",type=Path,help="Subscription output")
    parser.add_argument("device_id",type=lambda x: int(x,0),help="Device ID (ignored for subscription time logic)")
    parser.add_argument("start",type=lambda x: int(x,0),help="start timestamp from CLI (ignored in code!)")
    parser.add_argument("end",type=int,help="end timestamp from CLI (ignored in code!)")
    parser.add_argument("channel",type=int,help="Channel to subscribe to")
    return parser.parse_args()

def main():
    args = parse_args()
    subscription = gen_subscription(
        args.secrets_file.read(),
        args.device_id,
        args.start,
        args.end,
        args.channel
    )

    logger.debug(f"Generated subscription: {subscription}")
    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)

    logger.success(f"Wrote subscription to {str(args.subscription_file.absolute())}")

if __name__ == "__main__":
    main()
