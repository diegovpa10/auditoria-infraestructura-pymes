"""Pipeline Capa Oro Geoespacial: agregación municipal de unidades económicas,
cruce de exposición geo-tecnológica, linaje criptográfico y generación de visualizaciones cartográficas.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import geopandas as gpd
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from shapely.geometry import Point

RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "bronze"))
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "silver"))
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "gold"))

from common import RAIZ, utcnow  # noqa: E402
from calidad import MUNICIPIOS_COLIMA, esquema_denue_gold  # noqa: E402

# Coordenadas aproximadas de referencia de centroides municipales de Colima
CENTROIDES_MUNICIPIOS = {
    "Armería": (18.936, -103.965),
    "Colima": (19.243, -103.725),
    "Comala": (19.324, -103.758),
    "Coquimatlán": (19.205, -103.805),
    "Cuauhtémoc": (19.328, -103.602),
    "Ixtlahuacán": (18.998, -103.738),
    "Manzanillo": (19.052, -104.316),
    "Minatitlán": (19.384, -104.053),
    "Tecomán": (18.913, -103.876),
    "Villa de Álvarez": (19.266, -103.738),
}

CVE_MUNICIPIOS = {
    "Armería": 1,
    "Colima": 2,
    "Comala": 3,
    "Coquimatlán": 4,
    "Cuauhtémoc": 5,
    "Ixtlahuacán": 6,
    "Manzanillo": 7,
    "Minatitlán": 8,
    "Tecomán": 9,
    "Villa de Álvarez": 10,
}


def construir_resumen_municipal(df_silver_geo: pd.DataFrame) -> pd.DataFrame:
    """Agrega las unidades económicas de DENUE por municipio con linaje criptográfico."""
    filas = []
    total_estatal = len(df_silver_geo)

    for mun in MUNICIPIOS_COLIMA:
        sub = df_silver_geo[df_silver_geo["municipio"] == mun]
        cve_mun = CVE_MUNICIPIOS[mun]
        n_pymes = len(sub)

        if n_pymes > 0:
            micro = int((sub["estrato_personal"] == "0 a 5 personas").sum())
            peq = int((sub["estrato_personal"] == "6 a 10 personas").sum())
            med = int((sub["estrato_personal"].isin(["11 a 30 personas", "31 a 50 personas"])).sum())
            lat_c = round(float(sub["latitud"].mean()), 6)
            lon_c = round(float(sub["longitud"].mean()), 6)
            pct = round((n_pymes / total_estatal * 100.0) if total_estatal else 0.0, 2)
            arch_bronce = str(sub["archivo_origen_bronce"].iloc[0])
            f_bronce = str(sub["fecha_ingesta_bronce_utc"].iloc[0])
            sha_bronce = str(sub["sha256_origen_bronce"].iloc[0])
        else:
            micro = peq = med = 0
            lat_c, lon_c = CENTROIDES_MUNICIPIOS[mun]
            pct = 0.0
            arch_bronce = "denue/denue_colima_quimicos.json.gz"
            f_bronce = str(df_silver_geo["fecha_ingesta_bronce_utc"].iloc[0]) if not df_silver_geo.empty else utcnow().isoformat()
            sha_bronce = str(df_silver_geo["sha256_origen_bronce"].iloc[0]) if not df_silver_geo.empty else "0000000000000000"

        id_linaje = hashlib.sha256(f"{mun}_{cve_mun}_{sha_bronce}".encode()).hexdigest()[:16]

        filas.append(
            {
                "municipio": mun,
                "cve_mun": cve_mun,
                "total_pymes": n_pymes,
                "micro_0_a_5": micro,
                "pequenas_6_a_10": peq,
                "medianas_11_a_30": med,
                "latitud_centroide": lat_c,
                "longitud_centroide": lon_c,
                "pct_concentracion_estatal": pct,
                "archivo_origen_bronce": arch_bronce,
                "fecha_ingesta_bronce_utc": f_bronce,
                "sha256_origen_bronce": sha_bronce,
                "id_linaje": id_linaje,
            }
        )

    resumen = pd.DataFrame(filas).sort_values("total_pymes", ascending=False).reset_index(drop=True)
    return esquema_denue_gold().validate(resumen, lazy=True)


def construir_exposicion_geo_tecnologica(
    df_mun_gold: pd.DataFrame, df_series_gold: pd.DataFrame
) -> pd.DataFrame:
    """Cruza la densidad municipal de distribuidoras con el perfil de riesgo cibernético agregado."""
    # Métrica resumen de severidad tecnológica de los 6 grupos pyme
    cvss_promedio_global = round(float(df_series_gold["cvss_promedio"].mean()), 2)
    pico_critico_global = int(df_series_gold["cves_criticos"].max())
    total_explotados_kev = int(df_series_gold["conteo_kev"].sum())

    filas = []
    for _, r in df_mun_gold.iterrows():
        n_pymes = int(r["total_pymes"])
        # Score ponderado: mayor exposición donde coexisten más distribuidores sin TI interno
        # ponderado por la severidad CVSS base promedio del parque tecnológico
        score_exposicion = round((n_pymes * (cvss_promedio_global / 10.0) * 1.5), 2)
        if score_exposicion >= 15.0:
            nivel = "Critico"
        elif score_exposicion >= 7.0:
            nivel = "Alto"
        elif score_exposicion >= 2.0:
            nivel = "Medio"
        elif score_exposicion > 0.0:
            nivel = "Bajo"
        else:
            nivel = "Sin_Exposicion"

        filas.append(
            {
                "municipio": r["municipio"],
                "cve_mun": r["cve_mun"],
                "total_pymes_distribucion": n_pymes,
                "pct_distribuidoras_estatal": r["pct_concentracion_estatal"],
                "cvss_promedio_parque_ti": cvss_promedio_global,
                "vulnerabilidades_criticas_pico": pico_critico_global,
                "total_explotadas_kev": total_explotados_kev,
                "score_exposicion_combinado": score_exposicion,
                "nivel_riesgo_geoespacial": nivel,
                "archivos_origen_bronce": f"{r['archivo_origen_bronce']};nvd;kev",
                "fecha_ingesta_bronce": r["fecha_ingesta_bronce_utc"],
                "sha256_origen_bronce": r["sha256_origen_bronce"],
                "id_linaje": hashlib.sha256(f"{r['municipio']}_expo_{r['sha256_origen_bronce']}".encode()).hexdigest()[:16],
            }
        )

    return pd.DataFrame(filas).sort_values("score_exposicion_combinado", ascending=False).reset_index(drop=True)


def generar_visualizacion_cartografica(
    df_silver_geo: pd.DataFrame,
    df_mun_gold: pd.DataFrame,
    ruta_salida_png: Path,
    ruta_salida_html: Path | None = None,
) -> None:
    """Genera mapa cartográfico formal con GeoPandas y Matplotlib (PNG) y mapa interactivo (HTML)."""
    ruta_salida_png.parent.mkdir(parents=True, exist_ok=True)

    # 1. GeoDataFrames
    gdf_puntos = gpd.GeoDataFrame(
        df_silver_geo,
        geometry=gpd.points_from_xy(df_silver_geo["longitud"], df_silver_geo["latitud"]),
        crs="EPSG:4326",
    )
    gdf_mun = gpd.GeoDataFrame(
        df_mun_gold,
        geometry=gpd.points_from_xy(df_mun_gold["longitud_centroide"], df_mun_gold["latitud_centroide"]),
        crs="EPSG:4326",
    )

    fig, ax = plt.subplots(figsize=(10, 8), dpi=300)

    # Cobertura y límites de Colima
    ax.set_facecolor("#f8f9fa")
    fig.patch.set_facecolor("white")

    # Polígono simplificado del estado de Colima como marco cartográfico
    colima_box = [-104.5, 18.6, -103.4, 19.6]
    ax.set_xlim(colima_box[0], colima_box[2])
    ax.set_ylim(colima_box[1], colima_box[3])

    # Burbujas municipales proporcionales al total de pymes de distribución química
    tamanos = (df_mun_gold["total_pymes"] * 45) + 80
    scatter_mun = ax.scatter(
        df_mun_gold["longitud_centroide"],
        df_mun_gold["latitud_centroide"],
        s=tamanos,
        c=df_mun_gold["total_pymes"],
        cmap="YlOrRd",
        alpha=0.6,
        edgecolors="#7f0000",
        linewidth=1.5,
        label="Concentración municipal",
        zorder=3,
    )

    # Puntos de establecimientos individuales (anonimizados)
    ax.scatter(
        gdf_puntos["longitud"],
        gdf_puntos["latitud"],
        s=18,
        color="#003366",
        alpha=0.75,
        marker="o",
        label="Distribuidora de químicos (DENUE)",
        zorder=4,
    )

    # Etiquetas de municipios con conteos
    for _, r in df_mun_gold.iterrows():
        if r["total_pymes"] > 0:
            ax.annotate(
                f"{r['municipio']}\n({r['total_pymes']} pymes)",
                xy=(r["longitud_centroide"], r["latitud_centroide"]),
                xytext=(0, 10),
                textcoords="offset points",
                ha="center",
                fontsize=8,
                fontweight="bold",
                color="#1a1a1a",
                bbox=dict(boxstyle="round,pad=0.2", facecolor="white", alpha=0.8, edgecolor="#cccccc"),
                zorder=5,
            )

    # Cuadrícula y marco cartográfico
    ax.grid(True, linestyle="--", alpha=0.4, color="#999999")
    ax.set_xlabel("Longitud (°O)", fontsize=10, fontweight="bold")
    ax.set_ylabel("Latitud (°N)", fontsize=10, fontweight="bold")
    ax.set_title(
        "Observatorio PYMES Colima · Distribución Geoespacial del Sector Químico\n"
        "Directorio Estadístico Nacional de Unidades Económicas (DENUE - INEGI)",
        fontsize=12,
        fontweight="bold",
        pad=15,
    )

    # Barra de color para concentración municipal
    cbar = plt.colorbar(scatter_mun, ax=ax, shrink=0.7, pad=0.03)
    cbar.set_label("Número de Establecimientos por Municipio", fontsize=9, fontweight="bold")

    # Flecha de Norte
    ax.annotate(
        "N",
        xy=(-103.52, 19.48),
        xytext=(-103.52, 19.40),
        arrowprops=dict(facecolor="#1a1a1a", width=2.5, headwidth=8),
        ha="center",
        va="center",
        fontsize=11,
        fontweight="bold",
        zorder=6,
    )

    # Leyenda
    ax.legend(loc="lower left", framealpha=0.9, fontsize=8)

    plt.tight_layout()
    plt.savefig(ruta_salida_png, dpi=300)
    plt.close(fig)

    # Generación opcional de mapa interactivo HTML
    if ruta_salida_html:
        _generar_mapa_interactivo_html(df_silver_geo, df_mun_gold, ruta_salida_html)


def _generar_mapa_interactivo_html(
    df_silver_geo: pd.DataFrame, df_mun_gold: pd.DataFrame, ruta_html: Path
) -> None:
    """Genera visualizador interactivo standalone en HTML con Leaflet.js (sin dependencias externas en Python)."""
    puntos_json = []
    for _, r in df_silver_geo.iterrows():
        puntos_json.append(
            {
                "id": str(r["pyme_id"]),
                "mun": str(r["municipio"]),
                "act": str(r["nombre_act"]),
                "estrato": str(r["estrato_personal"]),
                "lat": float(r["latitud"]),
                "lon": float(r["longitud"]),
                "dist": float(r["distancia_centro_km"]),
            }
        )

    municipios_json = []
    for _, r in df_mun_gold.iterrows():
        municipios_json.append(
            {
                "mun": str(r["municipio"]),
                "total": int(r["total_pymes"]),
                "pct": float(r["pct_concentracion_estatal"]),
                "lat": float(r["latitud_centroide"]),
                "lon": float(r["longitud_centroide"]),
            }
        )

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8" />
  <title>Observatorio PYMES Colima · Mapa Geoespacial DENUE</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <style>
    body {{ margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    #map {{ height: 100vh; width: 100vw; }}
    .info-panel {{
      position: absolute; top: 10px; right: 10px; z-index: 1000;
      background: rgba(255, 255, 255, 0.95); padding: 15px; border-radius: 8px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.2); max-width: 320px; font-size: 13px;
    }}
    .info-panel h3 {{ margin: 0 0 8px 0; font-size: 15px; color: #003366; }}
    .badge {{ display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; background: #e0f2fe; color: #0369a1; font-weight: bold; }}
  </style>
</head>
<body>
  <div id="map"></div>
  <div class="info-panel">
    <h3>Observatorio PYMES · Sector Químico</h3>
    <p><b>Fuente:</b> INEGI DENUE (Colima, Entidad 06)</p>
    <p><b>Establecimientos anonimizados:</b> <span class="badge">{len(df_silver_geo)} pymes</span></p>
    <p><b>Municipios:</b> {len(df_mun_gold[df_mun_gold['total_pymes'] > 0])} activos</p>
    <p style="font-size: 11px; color: #666;">Haga clic en los marcadores para inspeccionar el estrato de empleo y la distancia al centro comercial.</p>
  </div>
  <script>
    const map = L.map('map').setView([19.15, -103.85], 10);
    L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
      attribution: '&copy; OpenStreetMap contributors | INEGI DENUE'
    }}).addTo(map);

    const puntos = {json.dumps(puntos_json)};
    const municipios = {json.dumps(municipios_json)};

    municipios.forEach(m => {{
      if (m.total > 0) {{
        L.circle([m.lat, m.lon], {{
          color: '#d97706',
          fillColor: '#f59e0b',
          fillOpacity: 0.25,
          radius: Math.sqrt(m.total) * 1200
        }}).bindTooltip(`<b>${{m.mun}}</b>: ${{m.total}} pymes (${{m.pct}}%)`).addTo(map);
      }}
    }});

    puntos.forEach(p => {{
      const marker = L.circleMarker([p.lat, p.lon], {{
        radius: 6,
        fillColor: '#0284c7',
        color: '#0369a1',
        weight: 1.5,
        opacity: 1,
        fillOpacity: 0.8
      }}).addTo(map);
      marker.bindPopup(`
        <b>${{p.id}}</b><br/>
        <b>Municipio:</b> ${{p.mun}}<br/>
        <b>Actividad:</b> ${{p.act}}<br/>
        <b>Estrato:</b> ${{p.estrato}}<br/>
        <b>Distancia al centro:</b> ${{p.dist}} km
      `);
    }});
  </script>
</body>
</html>
"""
    ruta_html.write_text(html_content, encoding="utf-8")


def construir_linaje_maestro_gold(
    ruta_gold: Path,
    df_series: pd.DataFrame,
    df_modelo: pd.DataFrame,
    df_trazabilidad: pd.DataFrame,
    df_municipios: pd.DataFrame,
    df_exposicion: pd.DataFrame,
) -> pd.DataFrame:
    """Construye la matriz de linaje y trazabilidad de todos los artefactos de la Capa Oro."""
    ahora_utc = utcnow().isoformat()
    registros_linaje = [
        {
            "artefacto_oro": "series_mensuales.csv",
            "tipo_entidad": "Series Temporales Agregadas",
            "total_registros": len(df_series),
            "capa_origen": "Bronze (NVD + KEV)",
            "fuentes_bronce": "nvd/{grupo}/*.json.gz;kev/kev_*.json.gz",
            "primera_fecha_ingesta_bronce": df_series["fecha_ingesta_bronce"].min(),
            "ultima_fecha_ingesta_bronce": df_series["fecha_ingesta_bronce"].max(),
            "llave_trazabilidad": "id_linaje",
            "trazabilidad_100_pct": True,
            "generado_utc": ahora_utc,
            "sha256": hashlib.sha256((ruta_gold / "series_mensuales.csv").read_bytes()).hexdigest(),
        },
        {
            "artefacto_oro": "series_modelo.csv",
            "tipo_entidad": "Series Reducidas para Modelado",
            "total_registros": len(df_modelo),
            "capa_origen": "Gold (series_mensuales.csv)",
            "fuentes_bronce": "nvd/{grupo}/*.json.gz;kev/kev_*.json.gz",
            "primera_fecha_ingesta_bronce": df_modelo["fecha_ingesta_bronce"].min(),
            "ultima_fecha_ingesta_bronce": df_modelo["fecha_ingesta_bronce"].max(),
            "llave_trazabilidad": "id_linaje",
            "trazabilidad_100_pct": True,
            "generado_utc": ahora_utc,
            "sha256": hashlib.sha256((ruta_gold / "series_modelo.csv").read_bytes()).hexdigest(),
        },
        {
            "artefacto_oro": "trazabilidad_cve_oro.csv",
            "tipo_entidad": "Trazabilidad Granular CVE",
            "total_registros": len(df_trazabilidad),
            "capa_origen": "Bronze (NVD + KEV) via Silver",
            "fuentes_bronce": "nvd/{grupo}/*.json.gz;kev/kev_*.json.gz",
            "primera_fecha_ingesta_bronce": df_trazabilidad["fecha_ingesta_nvd_utc"].min(),
            "ultima_fecha_ingesta_bronce": df_trazabilidad["fecha_ingesta_nvd_utc"].max(),
            "llave_trazabilidad": "id_linaje",
            "trazabilidad_100_pct": True,
            "generado_utc": ahora_utc,
            "sha256": hashlib.sha256((ruta_gold / "trazabilidad_cve_oro.csv").read_bytes()).hexdigest(),
        },
        {
            "artefacto_oro": "denue_municipios_colima.csv",
            "tipo_entidad": "Resumen Geoespacial Municipal",
            "total_registros": len(df_municipios),
            "capa_origen": "Bronze (DENUE INEGI Colima)",
            "fuentes_bronce": "denue/denue_colima_quimicos.json.gz",
            "primera_fecha_ingesta_bronce": df_municipios["fecha_ingesta_bronce_utc"].min(),
            "ultima_fecha_ingesta_bronce": df_municipios["fecha_ingesta_bronce_utc"].max(),
            "llave_trazabilidad": "id_linaje",
            "trazabilidad_100_pct": True,
            "generado_utc": ahora_utc,
            "sha256": hashlib.sha256((ruta_gold / "denue_municipios_colima.csv").read_bytes()).hexdigest(),
        },
        {
            "artefacto_oro": "exposicion_geo_tecnologica.csv",
            "tipo_entidad": "Cruce Espacio-Temporal Riesgo",
            "total_registros": len(df_exposicion),
            "capa_origen": "Bronze (DENUE + NVD + KEV)",
            "fuentes_bronce": "denue/denue_colima_quimicos.json.gz;nvd;kev",
            "primera_fecha_ingesta_bronce": df_exposicion["fecha_ingesta_bronce"].min(),
            "ultima_fecha_ingesta_bronce": df_exposicion["fecha_ingesta_bronce"].max(),
            "llave_trazabilidad": "id_linaje",
            "trazabilidad_100_pct": True,
            "generado_utc": ahora_utc,
            "sha256": hashlib.sha256((ruta_gold / "exposicion_geo_tecnologica.csv").read_bytes()).hexdigest(),
        },
    ]
    df_linaje = pd.DataFrame(registros_linaje)
    df_linaje.to_csv(ruta_gold / "linaje_registros.csv", index=False, encoding="utf-8")
    return df_linaje


def ejecutar_pipeline_geo_gold(
    carpeta_silver: Path | None = None,
    carpeta_gold: Path | None = None,
    carpeta_docs: Path | None = None,
) -> dict:
    """Ejecuta el pipeline completo de agregación, cruce geo-tecnológico y mapas."""
    silver = carpeta_silver or (RAIZ / "data" / "silver")
    gold = carpeta_gold or (RAIZ / "data" / "gold")
    docs_e2 = carpeta_docs or (RAIZ / "docs" / "E2")
    gold.mkdir(parents=True, exist_ok=True)
    docs_e2.mkdir(parents=True, exist_ok=True)

    ruta_silver_geo = silver / "denue_colima_quimicos.csv"
    if not ruta_silver_geo.exists():
        raise FileNotFoundError(f"Archivo Silver Geo no encontrado: {ruta_silver_geo}")

    df_silver_geo = pd.read_csv(ruta_silver_geo)
    df_series_gold = pd.read_csv(gold / "series_mensuales.csv")
    df_modelo_gold = pd.read_csv(gold / "series_modelo.csv")
    df_trazabilidad_gold = pd.read_csv(gold / "trazabilidad_cve_oro.csv")

    # 1. Resumen municipal
    df_mun_gold = construir_resumen_municipal(df_silver_geo)
    ruta_mun = gold / "denue_municipios_colima.csv"
    df_mun_gold.to_csv(ruta_mun, index=False, encoding="utf-8")

    # 2. Cruce de exposición geo-tecnológica
    df_expo_gold = construir_exposicion_geo_tecnologica(df_mun_gold, df_series_gold)
    ruta_expo = gold / "exposicion_geo_tecnologica.csv"
    df_expo_gold.to_csv(ruta_expo, index=False, encoding="utf-8")

    # 3. Visualizaciones cartográficas
    ruta_png = docs_e2 / "mapa_exposicion_colima.png"
    ruta_html = docs_e2 / "mapa_distribucion.html"
    generar_visualizacion_cartografica(df_silver_geo, df_mun_gold, ruta_png, ruta_html)

    # 4. Matriz maestra de linaje
    df_linaje = construir_linaje_maestro_gold(
        gold,
        df_series_gold,
        df_modelo_gold,
        df_trazabilidad_gold,
        df_mun_gold,
        df_expo_gold,
    )

    resumen = {
        "ingestado_utc": utcnow().isoformat(),
        "total_pymes_procesadas": len(df_silver_geo),
        "municipios_representados": int(df_mun_gold["municipio"].nunique()),
        "mapa_png_generado": str(ruta_png),
        "mapa_html_generado": str(ruta_html),
        "sha256_denue_municipios": hashlib.sha256(ruta_mun.read_bytes()).hexdigest(),
        "sha256_exposicion_geo": hashlib.sha256(ruta_expo.read_bytes()).hexdigest(),
        "sha256_mapa_png": hashlib.sha256(ruta_png.read_bytes()).hexdigest(),
    }
    (gold / "denue_municipios_colima.csv.meta.json").write_text(
        json.dumps(resumen, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return resumen


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Pipeline Gold Geoespacial y Cartografía.")
    ap.add_argument("--silver", default=str(RAIZ / "data" / "silver"))
    ap.add_argument("--gold", default=str(RAIZ / "data" / "gold"))
    ap.add_argument("--docs", default=str(RAIZ / "docs" / "E2"))
    args = ap.parse_args(argv)

    res = ejecutar_pipeline_geo_gold(Path(args.silver), Path(args.gold), Path(args.docs))
    print(
        f"Gold Geo listo: {res['total_pymes_procesadas']} pymes en {res['municipios_representados']} municipios. "
        f"Mapas guardados en {res['mapa_png_generado']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
