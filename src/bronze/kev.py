"""Extractor CISA KEV: guarda una foto (snapshot) del catalogo completo con fecha de ingesta.

La serie de tiempo se deriva despues (capa Silver) de `dateAdded`, no de la fecha de descarga.
Revisa los terminos de uso de CISA antes de publicar los datos (ver docs/E0/propuesta.md).
"""
import argparse
import sys
from pathlib import Path

import requests

from common import RAIZ, guardar_raw, utcnow

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HEADERS = {"User-Agent": "observatorio-pymes-escolar/0.1 (proyecto academico TecNM Colima)"}


def descargar(session=None, url: str = URL) -> bytes:
    session = session or requests.Session()
    resp = session.get(url, headers=HEADERS, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"KEV respondio {resp.status_code}")
    datos = resp.json()
    if "vulnerabilities" not in datos or not datos["vulnerabilities"]:
        raise RuntimeError("El feed KEV no trae 'vulnerabilities'")
    import json
    return json.dumps(datos, sort_keys=True, ensure_ascii=False).encode("utf-8")


def main(argv=None, session=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--salida", default=str(RAIZ / "data" / "bronze" / "kev"))
    args = ap.parse_args(argv)
    contenido = descargar(session)
    ruta = Path(args.salida) / f"kev_{utcnow():%Y%m%d}.json.gz"
    meta = guardar_raw(ruta, contenido, {"fuente": "CISA KEV", "url": URL})
    print(f"KEV guardado: {ruta} ({meta['bytes_contenido']} bytes, sha256 {meta['sha256_contenido'][:12]}...)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
