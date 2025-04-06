"""
Author: TrustLab Team
Date: 2025

This source file is part of a secure satellite TV transmission system for MITRE's 2025
Embedded System CTF (eCTF). This code implements the key generation and secrets
management for the satellite TV system.

Copyright: Copyright (c) 2025
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
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list

    :returns: Contents of the secrets file
    """
    # Generate master key for the system (32 bytes for AES-256)
    master_key = get_random_bytes(KEY_SIZE)
    if isinstance(master_key, bytearray):
        master_key = bytes(master_key)

    # Generate a unique encoder ID for the system
    encoder_id = get_random_bytes(4)
    if isinstance(encoder_id, bytearray):
        encoder_id = bytes(encoder_id)

    # Generate an initialization sequence number
    initial_seq_num = 1

    # Generate the signature key
    signature_key = get_random_bytes(KEY_SIZE)
    if isinstance(signature_key, bytearray):
        signature_key = bytes(signature_key)

    # Create the secrets object with all the required cryptographic material
    secrets = {
        # List of valid channels
        "channels": channels,

        # Master key (base64 encoded to ensure JSON compatibility)
        "master_key": base64.b64encode(master_key).decode('ascii'),

        # Unique encoder identifier (base64 encoded)
        "encoder_id": base64.b64encode(encoder_id).decode('ascii'),

        # Initial sequence number for anti-replay protection
        "initial_seq_num": initial_seq_num,

        # System version and info - for potential future compatibility checks
        "version": "1.0",

        # Include a signature key for subscription validation
        "signature_key": base64.b64encode(signature_key).decode('ascii'),
    }

    # Log information about generated keys (for debugging only)
    logger.debug(f"Generated master key: {bytes_to_hex(master_key)}")
    logger.debug(f"Generated encoder ID: {bytes_to_hex(encoder_id)}")

    # Serialize to JSON and encode to bytes
    return json.dumps(secrets).encode()


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
             " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets"""
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
