"""Extractor NVD API 2.0 por grupo de tecnologia y ventana de publicacion (<= 120 dias).

- Idempotente: una ventana ya cerrada (terminada hace > 7 dias) no se vuelve a pedir.
- Respeta el limite de peticiones: pausa mayor sin API key (gratis en nvd.nist.gov/developers).
- Guarda la respuesta cruda + metadatos (URL, parametros, fecha, sha256) para linaje.

Los parametros y limites salen de memoria: verificalos en la documentacion oficial
antes de la entrega (docs/E0/propuesta.md, seccion "Pendientes de verificar").
"""
import argparse
import json
import os
import re
import sys
import time
from datetime import date, timedelta
from pathlib import Path

import requests

from common import RAIZ, cargar_grupos, guardar_raw, utcnow

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"User-Agent": "observatorio-pymes-escolar/0.1 (proyecto academico TecNM Colima)"}
DIAS_VENTANA = 119  # margen bajo el maximo de 120 dias consecutivos
POR_PAGINA = 2000


def ventanas(inicio: date, fin: date, dias: int = DIAS_VENTANA):
    a = inicio
    while a <= fin:
        b = min(a + timedelta(days=dias - 1), fin)
        yield a, b
        a = b + timedelta(days=1)


def slug(texto: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", texto.lower()).strip("-")


def pedir_pagina(session, params: dict, api_key: str | None, reintentos: int = 5):
    headers = dict(HEADERS)
    if api_key:
        headers["apiKey"] = api_key
    espera = 10
    for _ in range(reintentos):
        resp = session.get(URL, params=params, headers=headers, timeout=60)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (403, 429, 500, 502, 503, 504):
            time.sleep(espera)
            espera *= 2
            continue
        raise RuntimeError(f"NVD respondio {resp.status_code} para {params}")
    raise RuntimeError(f"NVD agoto reintentos para {params}")


def descargar_ventana(session, keyword: str, a: date, b: date, api_key=None, pausa=6.5):
    paginas, inicio_idx = [], 0
    while True:
        params = {
            "keywordSearch": keyword,
            "pubStartDate": f"{a.isoformat()}T00:00:00.000",
            "pubEndDate": f"{b.isoformat()}T23:59:59.999",
            "resultsPerPage": POR_PAGINA,
            "startIndex": inicio_idx,
        }
        datos = pedir_pagina(session, params, api_key)
        paginas.append({"params": params, "respuesta": datos})
        inicio_idx += datos.get("resultsPerPage", POR_PAGINA)
        if inicio_idx >= datos.get("totalResults", 0):
            break
        time.sleep(pausa)
    return json.dumps(paginas, sort_keys=True, ensure_ascii=False).encode("utf-8")


def main(argv=None, session=None, hoy: date | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--salida", default=str(RAIZ / "data" / "bronze" / "nvd"))
    ap.add_argument("--desde")
    ap.add_argument("--hasta")
    ap.add_argument("--grupo", help="procesar solo un grupo")
    args = ap.parse_args(argv)

    session = session or requests.Session()
    hoy = hoy or utcnow().date()
    cfg = cargar_grupos()
    desde = date.fromisoformat(args.desde or cfg["desde"])
    hasta = date.fromisoformat(args.hasta) if args.hasta else hoy
    api_key = os.environ.get("NVD_API_KEY") or None
    pausa = 0.7 if api_key else 6.5

    nuevos = omitidos = 0
    for grupo, info in cfg["grupos"].items():
        if args.grupo and grupo != args.grupo:
            continue
        for kw in info["keywords"]:
            for a, b in ventanas(desde, hasta):
                ruta = Path(args.salida) / grupo / f"{slug(kw)}_{a}_{b}.json.gz"
                if ruta.exists() and b < hoy - timedelta(days=7):
                    omitidos += 1
                    continue
                contenido = descargar_ventana(session, kw, a, b, api_key, pausa)
                guardar_raw(ruta, contenido, {
                    "fuente": "NVD API 2.0", "url": URL, "grupo": grupo,
                    "keyword": kw, "ventana": [a.isoformat(), b.isoformat()],
                    "con_api_key": bool(api_key),
                })
                nuevos += 1
                time.sleep(pausa)
    print(f"NVD: {nuevos} ventanas descargadas, {omitidos} omitidas (ya existian)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
