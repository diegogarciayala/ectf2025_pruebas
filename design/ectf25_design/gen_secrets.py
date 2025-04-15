#!/usr/bin/env python3
"""
Archivo: gen_secrets.py
Genera un JSON muy simple con:
  {
    "decoder_id": <int>,
    "channels": [0, 1, ...]
  }
"""

import argparse
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output_file", type=Path, help="Dónde guardar el JSON con secrets")
    parser.add_argument("decoder_id", help="ID en hex. Ej: 0xDEADBEEF")
    parser.add_argument("channels", nargs="+", type=int, help="Canales disponibles (ej: 0 1 2)")
    parser.add_argument("--force", "-f", action="store_true", help="Sobrescribir si ya existe")
    args = parser.parse_args()

    # Convertimos la string "0xDEADBEEF" a int
    dec_id = int(args.decoder_id, 0)

    secrets = {
        "decoder_id": dec_id,
        "channels": args.channels
    }

    mode = "w" if args.force else "x"
    with open(args.output_file, mode) as f:
        json.dump(secrets, f, indent=2)
    print(f"Se escribió {args.output_file} con decoder_id={hex(dec_id)} y channels={args.channels}")

if __name__ == "__main__":
    main()
