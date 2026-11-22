"""Pipeline Capa Silver Geoespacial: limpieza, anonimización (Cero Datos Personales),
transformación con GeoPandas, cálculo de distancias euclidianas y validación Pandera con cuarentena.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import geopandas as gpd
import numpy as np
import pandas as pd
from shapely.geometry import Point

RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "bronze"))
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "silver"))

from common import RAIZ, leer_raw, utcnow  # noqa: E402
from calidad import esquema_denue_silver, validar_con_cuarentena  # noqa: E402

# Coordenadas de referencia del centro neurálgico comercial de la capital (Colima)
LAT_CENTRO_COLIMA = 19.2433
LON_CENTRO_COLIMA = -103.7247


def anonimizar_y_preparar_denue(filas: list[dict], meta_bronce: dict) -> pd.DataFrame:
    """Aplica el principio de minimización y Cero Datos Personales.
    Sustituye nombres comerciales y razones sociales por identificadores disociados (PYME-DIST-COL-XXX).
    """
    df = pd.DataFrame(filas)
    if df.empty:
        return pd.DataFrame(
            columns=[
                "pyme_id",
                "clee",
                "codigo_act",
                "nombre_act",
                "estrato_personal",
                "municipio",
                "cve_mun",
                "latitud",
                "longitud",
                "distancia_centro_km",
                "archivo_origen_bronce",
                "fecha_ingesta_bronce_utc",
                "sha256_origen_bronce",
                "id_linaje",
            ]
        )

    # Orden determinista para asignación estable de seudónimos
    df = df.sort_values(by=["cve_mun", "id"] if "id" in df.columns else ["cve_mun"]).reset_index(drop=True)
    df["pyme_id"] = [f"PYME-DIST-COL-{i+1:03d}" for i in range(len(df))]

    # Normalización de columnas numéricas y de texto
    df["codigo_act"] = pd.to_numeric(df.get("codigo_act"), errors="coerce").fillna(464111).astype(int)
    df["nombre_act"] = df.get("nombre_act", "Comercio al por mayor de fertilizantes y plaguicidas").astype(str)
    df["estrato_personal"] = df.get("per_ocu", "0 a 5 personas").fillna("0 a 5 personas").astype(str)
    df["municipio"] = df.get("municipio", "Colima").astype(str)
    df["cve_mun"] = pd.to_numeric(df.get("cve_mun"), errors="coerce").fillna(1).astype(int)
    df["latitud"] = pd.to_numeric(df.get("latitud"), errors="coerce")
    df["longitud"] = pd.to_numeric(df.get("longitud"), errors="coerce")
    df["clee"] = df.get("clee", None)

    # Linaje a nivel registro
    archivo_bronce = meta_bronce.get("archivo", "denue/denue_colima_quimicos.json.gz")
    sha256_bronce = meta_bronce.get("sha256_contenido", "desconocido")
    fecha_bronce = meta_bronce.get("ingestado_utc", utcnow().isoformat())

    df["archivo_origen_bronce"] = archivo_bronce
    df["fecha_ingesta_bronce_utc"] = fecha_bronce
    df["sha256_origen_bronce"] = sha256_bronce
    df["id_linaje"] = [
        hashlib.sha256(f"{pid}_{cm}_{sha256_bronce}".encode()).hexdigest()[:16]
        for pid, cm in zip(df["pyme_id"], df["cve_mun"])
    ]

    # Transformación geoespacial con GeoPandas: WGS84 -> UTM 13N métrico para cálculo de distancia
    gdf = gpd.GeoDataFrame(
        df,
        geometry=gpd.points_from_xy(df["longitud"], df["latitud"]),
        crs="EPSG:4326",
    )
    # Centro comercial de referencia en Colima
    pto_centro_wgs84 = gpd.GeoSeries([Point(LON_CENTRO_COLIMA, LAT_CENTRO_COLIMA)], crs="EPSG:4326")
    pto_centro_utm = pto_centro_wgs84.to_crs(epsg=32613).iloc[0]

    gdf_utm = gdf.to_crs(epsg=32613)
    distancias_metros = gdf_utm.geometry.distance(pto_centro_utm)
    df["distancia_centro_km"] = (distancias_metros / 1000.0).round(2)

    columnas_finales = [
        "pyme_id",
        "clee",
        "codigo_act",
        "nombre_act",
        "estrato_personal",
        "municipio",
        "cve_mun",
        "latitud",
        "longitud",
        "distancia_centro_km",
        "archivo_origen_bronce",
        "fecha_ingesta_bronce_utc",
        "sha256_origen_bronce",
        "id_linaje",
    ]
    return df[columnas_finales].copy()


def ejecutar_pipeline_geo_silver(
    carpeta_bronze: Path | None = None,
    carpeta_silver: Path | None = None,
    carpeta_cuarentena: Path | None = None,
    datos_inyectados: list[dict] | None = None,
    meta_inyectada: dict | None = None,
) -> dict:
    """Ejecuta el pipeline Bronze -> Silver de DENUE con puerta de calidad Pandera."""
    bronze = carpeta_bronze or (RAIZ / "data" / "bronze" / "denue")
    silver = carpeta_silver or (RAIZ / "data" / "silver")
    cuarentena_dir = carpeta_cuarentena or (RAIZ / "data" / "cuarentena")
    silver.mkdir(parents=True, exist_ok=True)
    cuarentena_dir.mkdir(parents=True, exist_ok=True)

    if datos_inyectados is not None:
        crudos = datos_inyectados
        meta_bronce = meta_inyectada or {"archivo": "simulado", "sha256_contenido": "hash_simulado"}
    else:
        ruta_archivo = bronze / "denue_colima_quimicos.json.gz"
        if not ruta_archivo.exists():
            raise FileNotFoundError(f"Archivo Bronze no encontrado: {ruta_archivo}")
        crudos = leer_raw(ruta_archivo)
        ruta_meta = bronze / "denue_colima_quimicos.json.gz.meta.json"
        meta_bronce = json.loads(ruta_meta.read_text(encoding="utf-8")) if ruta_meta.exists() else {}

    df_preparado = anonimizar_y_preparar_denue(crudos, meta_bronce)

    # Puerta de Calidad Pandera
    validos, cuarentena = validar_con_cuarentena(
        df_preparado,
        esquema_denue_silver(),
        etapa="puerta_denue_silver",
    )

    ruta_salida = silver / "denue_colima_quimicos.csv"
    validos.to_csv(ruta_salida, index=False, encoding="utf-8")

    ruta_cuar = cuarentena_dir / "cuarentena_denue.csv"
    cuarentena.to_csv(ruta_cuar, index=False, encoding="utf-8")

    resumen = {
        "ingestado_utc": utcnow().isoformat(),
        "registros_bronce": len(crudos),
        "registros_silver_validos": len(validos),
        "registros_cuarentena": len(cuarentena),
        "municipios_representados": int(validos["municipio"].nunique()) if not validos.empty else 0,
        "sha256_silver": hashlib.sha256(ruta_salida.read_bytes()).hexdigest(),
    }
    (silver / "denue_colima_quimicos.csv.meta.json").write_text(
        json.dumps(resumen, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return resumen


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Pipeline Silver Geoespacial DENUE.")
    ap.add_argument("--bronze", default=str(RAIZ / "data" / "bronze" / "denue"))
    ap.add_argument("--silver", default=str(RAIZ / "data" / "silver"))
    ap.add_argument("--cuarentena", default=str(RAIZ / "data" / "cuarentena"))
    args = ap.parse_args(argv)

    res = ejecutar_pipeline_geo_silver(Path(args.bronze), Path(args.silver), Path(args.cuarentena))
    print(
        f"DENUE Silver listo: {res['registros_silver_validos']} establecimientos anonimizados "
        f"en {res['municipios_representados']} municipios ({res['registros_cuarentena']} en cuarentena)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
