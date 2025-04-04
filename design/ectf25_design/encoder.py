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
import struct
from pathlib import Path
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from Crypto.Util import Counter


def derive_cmac(key: bytes, data: bytes) -> bytes:
    """Genera un CMAC utilizando AES y devuelve el valor final."""
    c = CMAC.new(key, ciphermod=AES)
    c.update(data)
    return c.digest()


class Encoder:
    def __init__(self, secrets_data: bytes, subscription_data: bytes):
        """
        Inicializa el encoder cargando los secretos y la suscripción.
        :param secrets_data: Contenido del archivo de secretos (JSON).
        :param subscription_data: Contenido del archivo de suscripción (binario).
        """
        secrets = json.loads(secrets_data)
        # La clave maestra debe coincidir con la utilizada en gen_secrets.py
        self.K_master = b'my_sup3r53cur3_K1_m45ter'
        try:
            self.encoder_id = int(secrets["ENCODER_ID"])
        except KeyError:
            raise ValueError("El archivo de secretos debe contener el campo 'ENCODER_ID'.")

        try:
            self.T_inicio = int(secrets["T_inicio"])
            self.T_fin = int(secrets["T_fin"])
            self.subscription_channels = secrets["channels"]
            self.decoder_id = int(secrets["DECODER_ID"])
        except KeyError as e:
            raise ValueError(f"Falta el campo {e} en el archivo de secretos para la suscripción.")

        # Bloque de suscripción ya generado (se usa sin modificaciones)
        self.subscription_code = subscription_data

        # Contador de secuencia inicial
        self.seq = 0
        # Derivar K1 inicial usando seq//2 representado en 10 bytes big-endian
        self.K1 = derive_cmac(self.K_master, (self.seq // 2).to_bytes(10, byteorder="big"))

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """
        Cifra una trama usando AES-CTR con una clave dinámica derivada de K1.
        El paquete final tiene el siguiente formato:
          HEADER || C_SUBS || CIPHERTEXT
        Donde:
          HEADER = (#SEQ ∥ CH_ID ∥ ENCODER_ID) (cada uno 4 bytes little-endian)
          C_SUBS = bloque de suscripción (ya generado externamente)
          CIPHERTEXT = cifrado de [FRAME ∥ TS ∥ #SEQ] (donde TS es 8 bytes little-endian y #SEQ 4 bytes little-endian)
        """
        # Actualizar K1 cada dos tramas
        if self.seq % 2 == 0:
            self.K1 = derive_cmac(self.K_master, (self.seq // 2).to_bytes(10, byteorder="big"))

        # Construir nonce para AES-CTR:
        # Se define un contador con prefijo = [#SEQ (4 bytes big-endian) || CH_ID (4 bytes big-endian)]
        prefix = struct.pack(">II", self.seq, channel)
        # El contador ocupará 8 bytes (64 bits)
        ctr = Counter.new(64, prefix=prefix, initial_value=0, little_endian=False)

        # Cifrar la carga: FRAME || TS || #SEQ (TS y #SEQ en little-endian)
        plaintext = frame + struct.pack("<Q", timestamp) + struct.pack("<I", self.seq)
        cipher = AES.new(self.K1, AES.MODE_CTR, counter=ctr)
        ciphertext = cipher.encrypt(plaintext)

        # Construir el header: (#SEQ, CH_ID, ENCODER_ID) en little-endian (cada uno 4 bytes)
        header = struct.pack("<III", self.seq, channel, self.encoder_id)

        # Incrementar el contador de secuencia para la siguiente llamada
        self.seq += 1

        return header + self.subscription_code + ciphertext


def parse_args():
    """Define y parse los argumentos de la línea de comandos"""
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument(
        "secrets_file", type=Path, help="Ruta al archivo de secretos generado por gen_secrets.py"
    )
    parser.add_argument(
        "subscription_file", type=Path, help="Ruta al archivo de suscripción generado por gen_subscription.py"
    )
    parser.add_argument("channel", type=int, help="Canal para el cual cifrar la trama")
    parser.add_argument("frame", help="Contenido de la trama a cifrar")
    parser.add_argument("timestamp", type=int, help="Timestamp (64b) a incluir en la trama")
    return parser.parse_args()


def main():
    """Función de prueba para cifrar una trama"""
    args = parse_args()
    secrets_data = args.secrets_file.read_bytes()
    subscription_data = args.subscription_file.read_bytes()
    encoder = Encoder(secrets_data, subscription_data)
    encoded_packet = encoder.encode(args.channel, args.frame.encode(), args.timestamp)
    print(repr(encoded_packet))


if __name__ == "__main__":
    main()
