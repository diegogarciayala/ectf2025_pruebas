#!/usr/bin/env python3
# gen_subscription.py

import argparse
import json
import struct
from pathlib import Path
from loguru import logger
import base64


def load_secrets(secrets_file: Path):
    """Carga los secretos desde un archivo JSON"""
    with open(secrets_file, 'r') as f:
        secrets = json.load(f)
    return secrets


def gen_subscription(secrets: dict, subscription_file: Path):
    """Genera un archivo de suscripción en formato binario basado en los secretos"""

    # Inicia el archivo binario
    with open(subscription_file, 'wb') as f:
        # Escribir la cabecera del archivo binario
        header = b'SUBSCRIPTION_HEADER'
        f.write(header)

        # Escribir los canales y sus claves
        for channel_id in secrets['channels']:
            channel_key = secrets['channel_keys'][str(channel_id)].encode()

            # Para el canal de emergencia (0) se utiliza una clave fija
            if channel_id == 0:
                emergency_channel = base64.b64encode(b'emergency_channel_key')
                f.write(emergency_channel)

            # Empaquetar el ID del canal (4 bytes) y la longitud de la clave (4 bytes), luego la clave
            channel_id_bytes = struct.pack(">I", channel_id)
            f.write(channel_id_bytes)
            f.write(struct.pack(">I", len(channel_key)))
            f.write(channel_key)

        footer = b'SUBSCRIPTION_FOOTER'
        f.write(footer)

    logger.success(f"Suscripción generada correctamente en {subscription_file}")


def parse_args():
    """Define y parse los argumentos de la línea de comandos"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Ruta al archivo de secretos generado por gen_secrets.py",
    )
    parser.add_argument(
        "subscription_file",
        type=Path,
        help="Ruta donde se almacenará el archivo de suscripción binario generado",
    )
    return parser.parse_args()


def main():
    """Función principal para generar la suscripción binaria"""
    args = parse_args()
    secrets = load_secrets(args.secrets_file)
    gen_subscription(secrets, args.subscription_file)


if __name__ == "__main__":
    main()
