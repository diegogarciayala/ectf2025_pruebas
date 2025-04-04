"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import base64
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def derive_cmac(key: bytes, data: bytes) -> bytes:
    """Genera un CMAC utilizando AES y devuelve el valor final."""
    c = CMAC(algorithms.AES(key), backend=default_backend())
    c.update(data)
    return c.finalize()


class Encoder:
    def __init__(self, secrets_data: bytes, subscription_data: bytes):
        """
        Los archivos de secretos y suscripción ya han sido generados previamente mediante:
          - gen_secrets.py (genera secrets.json)
          - gen_subscription.py (genera el archivo de suscripción binario)

        :param secrets_data: Contenido del archivo de secretos (formato JSON)
        :param subscription_data: Contenido del archivo de suscripción (formato binario)
        """
        # Cargar el JSON de secretos
        secrets = json.loads(secrets_data)

        # Se espera que el archivo de secretos contenga al menos:
        #   "channels": lista de canales autorizados
        #   "channel_keys": claves derivadas para cada canal (en base64)
        # Para el proceso de encriptación de tramas, la clave dinámica (K1) se deriva a partir de
        # una clave maestra hardcodeada (la misma usada en gen_secrets.py).
        self.K_master = b'my_sup3r53cur3_K1_m45ter'

        # Se espera que el archivo de secretos incluya el identificador del encoder
        try:
            self.encoder_id = int(secrets["ENCODER_ID"])
        except KeyError:
            raise ValueError("El archivo de secretos debe contener el campo 'ENCODER_ID'.")

        # Guardar otros parámetros de suscripción (T_inicio, T_fin, canales autorizados y DECODER_ID)
        try:
            self.T_inicio = int(secrets["T_inicio"])
            self.T_fin = int(secrets["T_fin"])
            self.subscription_channels = secrets["channels"]
            self.decoder_id = int(secrets["DECODER_ID"])
        except KeyError as e:
            raise ValueError(f"Falta el campo {e} en el archivo de secretos para la suscripción.")

        # El bloque de suscripción (C_SUBS) ya fue generado y se pasa en subscription_data
        self.subscription_code = subscription_data

        # Inicializar el contador de secuencia
        self.seq = 0
        # Inicializar K1 derivándolo a partir de K_master y el contador (0 inicialmente)
        self.K1 = derive_cmac(self.K_master, (self.seq // 2).to_bytes(10, byteorder="big"))

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """
        Cifra la trama usando AES-CTR con una clave dinámica derivada de K1.

        Se construye el paquete final con el siguiente formato:
          (#SEQ ∥ CH_ID ∥ ENCODER_ID) || [C_SUBS] || [FRAME ∥ TS ∥ #SEQ] cifrado

        Donde:
          - #SEQ: número de secuencia (4 bytes little-endian)
          - CH_ID: identificador de canal (4 bytes little-endian)
          - ENCODER_ID: identificador del encoder (4 bytes little-endian)
          - C_SUBS: bloque de suscripción (generado externamente)
          - FRAME: contenido de la trama (hasta 64 bytes)
          - TS: timestamp (8 bytes little-endian)

        :param channel: Canal al que se envía la trama.
        :param frame: Trama a cifrar.
        :param timestamp: Timestamp (64b) a incluir en la carga.
        :returns: El paquete final listo para ser enviado.
        """
        # Actualizar K1 cada dos tramas para mejorar la seguridad
        if self.seq % 2 == 0:
            self.K1 = derive_cmac(self.K_master, (self.seq // 2).to_bytes(10, byteorder="big"))

        # Derivar el nonce para AES-CTR: concatenamos #SEQ y CH_ID (cada uno 4 bytes, big-endian)
        # y completamos con 8 bytes de ceros para formar un nonce de 16 bytes.
        nonce = struct.pack(">II", self.seq, channel) + b'\x00' * 8

        # Construir el plaintext: FRAME || TS || #SEQ
        plaintext = frame + struct.pack("<Q", timestamp) + struct.pack("<I", self.seq)

        # Encriptar usando AES-CTR
        cipher = Cipher(algorithms.AES(self.K1), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Construir el header: (#SEQ ∥ CH_ID ∥ ENCODER_ID) en little-endian (cada uno 4 bytes)
        header = struct.pack("<III", self.seq, channel, self.encoder_id)

        # Incrementar el contador de secuencia para la siguiente llamada
        self.seq += 1

        # Paquete final: header || bloque de suscripción || ciphertext
        return header + self.subscription_code + ciphertext


def main():
    """
    Función de prueba para cifrar una trama.

    Se espera que se invoque de la siguiente forma (tras haber generado secretos y suscripción):
      python3 -m ectf25_design.encoder \
             path/to/secrets.json \
             path/to/subscription.bin \
             <channel> \
             "<frame>" \
             <timestamp>
    """
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument("secrets_file", type=Path, help="Ruta al archivo de secretos generado por gen_secrets.py")
    parser.add_argument("subscription_file", type=Path,
                        help="Ruta al archivo de suscripción generado por gen_subscription.py")
    parser.add_argument("channel", type=int, help="Canal para el cual cifrar la trama")
    parser.add_argument("frame", help="Contenido de la trama a cifrar")
    parser.add_argument("timestamp", type=int, help="Timestamp (64b) a incluir en la trama")
    args = parser.parse_args()

    # Cargar el contenido de los archivos
    secrets_data = args.secrets_file.read_bytes()
    subscription_data = args.subscription_file.read_bytes()

    encoder = Encoder(secrets_data, subscription_data)
    encoded_packet = encoder.encode(args.channel, args.frame.encode(), args.timestamp)
    print(repr(encoded_packet))


if __name__ == "__main__":
    main()
