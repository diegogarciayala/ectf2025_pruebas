# gen_secrets.py

import argparse
import json
from loguru import logger

def gen_secrets(channels: list[int]) -> bytes:
    """
    Devuelve un JSON con "channels" y lo que necesites (por ejemplo decoder_id).
    Lo retornamos en formato bytes (como solía hacerse en el pipeline anterior).
    """
    data = {
        "decoder_id": 0xDEADBEEF,  # Ejemplo
        "channels": channels
    }
    # Convertimos el dict a JSON y luego a bytes
    secrets_bytes = json.dumps(data).encode('utf-8')
    return secrets_bytes

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("secrets_file", help="Ruta de salida para global.secrets")
    parser.add_argument("channels", nargs="+", type=int, help="Listado de canales")
    parser.add_argument("--force","-f", action="store_true", help="Sobrescribe si ya existe")
    args = parser.parse_args()

    # Llamamos a la función con la misma lógica que tu pipeline
    secrets = gen_secrets(args.channels)

    # Guardamos en un fichero
    mode = "wb" if args.force else "xb"
    with open(args.secrets_file, mode) as f:
        f.write(secrets)

    logger.success(f"Se escribió {args.secrets_file} con {args.channels}")

if __name__ == "__main__":
    main()
