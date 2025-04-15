# gen_secrets.py (simplificado con la misma estructura que antes)

import json
from pathlib import Path

def gen_secrets(output_file: Path, decoder_id_hex: str, channels: list[int], force: bool = False):
    # Convertir el decoder_id desde string (ej: "0xDEADBEEF") a int
    dec_id = int(decoder_id_hex, 0)
    secrets = {
        "decoder_id": dec_id,
        "channels": channels
    }

    mode = "w" if force else "x"
    with open(output_file, mode) as f:
        json.dump(secrets, f, indent=2)

def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("output_file", type=Path)
    parser.add_argument("decoder_id")
    parser.add_argument("channels", nargs="+", type=int)
    parser.add_argument("--force", "-f", action="store_true")
    args = parser.parse_args()

    gen_secrets(args.output_file, args.decoder_id, args.channels, args.force)
    print(f"Se escribió {args.output_file} con decoder_id={args.decoder_id} y channels={args.channels}")

if __name__ == "__main__":
    main()
