"""Extractor Capa Bronze: Directorio Estadístico Nacional de Unidades Económicas (DENUE - INEGI).
Obtiene y almacena las unidades económicas de distribución y comercio al por mayor de
productos químicos, agroquímicos y fertilizantes en el estado de Colima (Entidad 06).
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import requests

from common import RAIZ, guardar_raw, utcnow

URL_DENUE_MASIVO_COLIMA = "https://www.inegi.org.mx/contenidos/masiva/denue/denue_06_csv.zip"
URL_DENUE_API = "https://www.inegi.org.mx/app/api/denue/v1/consulta/BuscarEntidad/{condicion}/06/1/1000/{token}"
USER_AGENT = "ObservatorioPymesColima/1.0 (investigacion academica; TecNM Colima)"

KEYWORDS_DISTRIBUCION_QUIMICA = [
    "fertiliz",
    "plaguic",
    "quimic",
    "químic",
    "agroquim",
    "agroquím",
]


def filtrar_establecimientos_quimicos(filas: list[dict]) -> list[dict]:
    """Filtra establecimientos del sector mayorista de distribución química en Colima."""
    filtrados = []
    for fila in filas:
        nombre_act = str(fila.get("nombre_act") or fila.get("Clase_actividad") or "")
        nombre_act_lower = nombre_act.lower()
        es_quimico = any(k in nombre_act_lower for k in KEYWORDS_DISTRIBUCION_QUIMICA)
        # Asegurar enfoque en distribución / comercio al por mayor
        es_comercio_mayor = (
            "comercio al por mayor" in nombre_act_lower
            or "distribui" in nombre_act_lower
            or str(fila.get("codigo_act") or "").startswith("46")
            or str(fila.get("codigo_act") or "").startswith("43")
        )
        if es_quimico and es_comercio_mayor:
            filtrados.append(fila)
    return filtrados


def extraer_denue_desde_zip(contenido_zip: bytes) -> list[dict]:
    """Extrae y parsea el archivo principal de unidades económicas desde el ZIP oficial de INEGI."""
    import pandas as pd

    zf = zipfile.ZipFile(io.BytesIO(contenido_zip))
    nombre_csv = next(
        (name for name in zf.namelist() if name.startswith("conjunto_de_datos/") and name.endswith(".csv")),
        None,
    )
    if not nombre_csv:
        # Búsqueda fallback de cualquier CSV en el zip
        nombre_csv = next((name for name in zf.namelist() if name.endswith(".csv") and "diccionario" not in name), None)

    if not nombre_csv:
        raise RuntimeError("No se encontró el conjunto de datos CSV en el archivo ZIP de INEGI DENUE.")

    with zf.open(nombre_csv) as f:
        df = pd.read_csv(f, encoding="latin1", low_memory=False)

    df_filtrado = df[
        df["nombre_act"].str.contains("fertiliz|plaguic|quimic|químic|agroquim", case=False, na=False)
        & df["nombre_act"].str.contains("comercio al por mayor|distribui", case=False, na=False)
    ]
    # Reemplazar NaN por None para serialización JSON estándar
    return df_filtrado.where(df_filtrado.notna(), None).to_dict(orient="records")


def descargar_denue_colima(
    session: requests.Session | None = None,
    token_api: str | None = None,
    url_masiva: str = URL_DENUE_MASIVO_COLIMA,
) -> tuple[list[dict], dict]:
    """Descarga datos de DENUE Colima vía API REST de INEGI o mediante paquete oficial masivo."""
    s = session or requests.Session()
    s.headers.setdefault("User-Agent", USER_AGENT)

    token = token_api or os.environ.get("INEGI_DENUE_TOKEN")

    # Intento 1: API REST si se cuenta con token
    if token:
        try:
            url_api = URL_DENUE_API.format(condicion="quimicos", token=token)
            resp = s.get(url_api, timeout=20)
            if resp.status_code == 200:
                datos = resp.json()
                if isinstance(datos, list) and len(datos) > 0:
                    filtrados = filtrar_establecimientos_quimicos(datos)
                    meta = {
                        "fuente": "INEGI DENUE API v1",
                        "url": url_api.replace(token, "[REDACTED]"),
                        "metodo": "BuscarEntidad",
                        "entidad": "06 - Colima",
                        "registros_obtenidos": len(filtrados),
                    }
                    return filtrados, meta
        except Exception:
            pass  # Fallback a descarga masiva oficial

    # Intento 2 / Principal: Descarga del paquete de datos abiertos oficial de Colima
    resp = s.get(url_masiva, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"Error al descargar DENUE Colima desde {url_masiva}: HTTP {resp.status_code}")

    # Si la respuesta es JSON directo (ej. respuestas simuladas en pruebas)
    if resp.headers.get("Content-Type", "").startswith("application/json") or resp.text.startswith("["):
        datos = resp.json()
        filtrados = filtrar_establecimientos_quimicos(datos) if isinstance(datos, list) else []
        meta = {
            "fuente": "INEGI DENUE Simulado/API",
            "url": url_masiva,
            "entidad": "06 - Colima",
            "registros_obtenidos": len(filtrados),
        }
        return filtrados, meta

    # Paquete ZIP binario oficial de INEGI
    registros = extraer_denue_desde_zip(resp.content)
    meta = {
        "fuente": "INEGI DENUE Datos Abiertos (Descarga Masiva)",
        "url": url_masiva,
        "entidad": "06 - Colima",
        "sector": "Comercio al por mayor de fertilizantes, plaguicidas y productos químicos",
        "terminos_uso": "Términos de Libre Uso de la Información del INEGI",
        "registros_obtenidos": len(registros),
    }
    return registros, meta


def main(argv=None, session: requests.Session | None = None) -> int:
    ap = argparse.ArgumentParser(description="Descarga y almacena en Capa Bronze el DENUE Colima.")
    ap.add_argument("--salida", default=str(RAIZ / "data" / "bronze" / "denue"))
    ap.add_argument("--token", default=None, help="Token opcional de la API de INEGI")
    args = ap.parse_args(argv)

    dir_salida = Path(args.salida)
    dir_salida.mkdir(parents=True, exist_ok=True)

    registros, meta_extra = descargar_denue_colima(session=session, token_api=args.token)
    if not registros:
        raise RuntimeError("La descarga de DENUE no devolvió registros.")

    contenido = json.dumps(registros, ensure_ascii=False, indent=2).encode("utf-8")
    destino = dir_salida / "denue_colima_quimicos.json.gz"

    metadatos = guardar_raw(
        destino,
        contenido,
        {
            **meta_extra,
            "archivo": destino.name,
            "total_registros": len(registros),
        },
    )
    print(
        f"DENUE guardado: {destino} ({metadatos['bytes_contenido']} bytes, "
        f"{metadatos['total_registros']} registros, sha256 {metadatos['sha256_contenido'][:12]}...)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
