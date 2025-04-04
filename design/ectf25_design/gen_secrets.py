#!/usr/bin/env python3
"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is provided only for educational purposes for the 2025 MITRE eCTF
competition, and may not meet MITRE standards for quality. Use this code at your own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import base64
import json
from pathlib import Path
from Crypto.Hash import CMAC
from Crypto.Cipher import AES


def derive_cmac(key: bytes, data: bytes) -> bytes:
    """Genera un CMAC utilizando AES y devuelve el valor final."""
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()


def gen_secrets(channels: list[int], K_master: bytes, secrets_file: Path) -> dict:
    """Genera el archivo de secretos con las claves de canal derivadas a partir de la clave maestra.

    :param channels: Lista de canales válidos.
    :param K_master: La clave maestra que se utiliza para derivar las claves.
    :param secrets_file: Ruta donde se guarda el archivo de secretos.

    :returns: Un diccionario con los secretos generados.
    """
    secrets = {}
    channel_keys = {}
    for i, channel_id in enumerate(channels):
        if i % 2 == 0:
            # Derivar la clave K1 usando el índice del canal en 10 bytes big-endian
            input_for_k1 = i.to_bytes(10, byteorder="big")
            K1 = derive_cmac(K_master, input_for_k1)
            print(f"k1_key --> {K1.hex()}")

        # Derivar la clave del canal usando K1 y el ID del canal (10 bytes big-endian)
        channel_key = derive_cmac(K1, channel_id.to_bytes(10, byteorder="big"))
        channel_keys[str(channel_id)] = base64.b64encode(channel_key).decode()

    secrets['channels'] = channels
    secrets['channel_keys'] = channel_keys
    # Se pueden agregar otros parámetros para la suscripción, como ENCODER_ID, T_inicio, T_fin, etc.
    with open(secrets_file, 'w') as f:
        json.dump(secrets, f, indent=4)

    print(f"Secrets written to {secrets_file}")
    return secrets


def parse_args():
    """Define y parse los argumentos de la línea de comandos"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Forzar la creación del archivo de secretos, sobrescribiendo el archivo existente",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Ruta al archivo de secretos que se creará",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Canales soportados. El canal 0 (broadcast) siempre es válido y no estará presente en esta lista",
    )
    return parser.parse_args()


def main():
    """Función principal para generar secretos"""
    args = parse_args()
    # La clave maestra hardcodeada (debe coincidir con la utilizada en el encoder)
    K_master = b'my_sup3r53cur3_K1_m45ter'
    gen_secrets(args.channels, K_master, args.secrets_file)


if __name__ == "__main__":
    main()
