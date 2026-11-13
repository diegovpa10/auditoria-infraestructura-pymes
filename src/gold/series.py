"""Pipeline Capa Oro (Gold): agregación mensual, detección y tratamiento de atípicos,
normalización Min-Max / Z-Score, discretización, jerarquías conceptuales y reducción de variables.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "bronze"))
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "silver"))

from common import RAIZ, cargar_grupos, utcnow  # noqa: E402
from calidad import MACRO_CATEGORIA_POR_GRUPO, esquema_gold  # noqa: E402

COLUMNAS_REDUCIDAS = [
    "grupo",
    "macro_categoria",
    "periodo",
    "anio",
    "trimestre",
    "total_cves",
    "total_cves_tratado",
    "total_cves_minmax",
    "total_cves_zscore",
    "cvss_promedio",
    "conteo_kev_catalogo",
    "conteo_ransomware",
    "nivel_riesgo_mensual",
]


def _minmax_seguro(s: pd.Series) -> pd.Series:
    rango = s.max() - s.min()
    if rango == 0 or pd.isna(rango):
        return pd.Series(0.0, index=s.index)
    return ((s - s.min()) / rango).round(6)


def _zscore_seguro(s: pd.Series) -> pd.Series:
    std = s.std(ddof=0)
    if std == 0 or pd.isna(std):
        return pd.Series(0.0, index=s.index)
    return ((s - s.mean()) / std).round(6)


def _tratar_atipicos_grupo(s: pd.Series) -> tuple[pd.Series, pd.Series, pd.Series]:
    """Aplica detección IQR y Z-Score robusto (MAD) y winsoriza picos extremos."""
    q1, q3 = s.quantile(0.25), s.quantile(0.75)
    iqr = q3 - q1
    if iqr > 0:
        lim_sup = q3 + 1.5 * iqr
        mask_iqr = s > lim_sup
        tratado = s.clip(upper=lim_sup).astype(float)
    else:
        mask_iqr = pd.Series(False, index=s.index)
        tratado = s.astype(float)

    med = s.median()
    mad = (s - med).abs().median()
    if mad > 0:
        z_rob = 0.6745 * (s - med) / mad
        mask_mad = z_rob.abs() > 3.5
    else:
        mask_mad = pd.Series(False, index=s.index)

    return tratado.round(2), mask_iqr, mask_mad


def _discretizar_riesgo_mensual(row: pd.Series) -> str:
    if row["total_cves"] == 0 and row["conteo_kev_catalogo"] == 0:
        return "Sin_Exposicion"
    if (
        row["conteo_kev"] > 0
        or row["conteo_kev_catalogo"] > 0
        or row["cves_criticos"] >= 2
        or row["cvss_max"] >= 9.0
    ):
        return "Critico"
    if row["cvss_max"] >= 7.0 or row["total_cves"] >= 10:
        return "Alto"
    if row["cvss_max"] >= 4.0:
        return "Medio"
    return "Bajo"


def construir_series_gold(
    df_silver: pd.DataFrame,
    grupos_validos: list[str],
    desde_periodo: str = "2021-11",
    hasta_periodo: str | None = None,
    df_kev_catalogo: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """Construye la tabla mensual Gold completa con transformaciones estadísticas."""
    if df_silver.empty and not hasta_periodo:
        raise ValueError("df_silver está vacío y no se especificó `hasta_periodo`")

    fin_periodo = hasta_periodo or str(df_silver["periodo"].max())
    periodos = [str(p) for p in pd.period_range(desde_periodo, fin_periodo, freq="M")]
    malla = pd.MultiIndex.from_product([grupos_validos, periodos], names=["grupo", "periodo"]).to_frame(index=False)

    if not df_silver.empty:
        agg_nvd = (
            df_silver.groupby(["grupo", "periodo"])
            .agg(
                total_cves=("cve_id", "count"),
                cves_criticos=("severidad_discreta", lambda s: int((s == "Critico").sum())),
                cves_altos=("severidad_discreta", lambda s: int((s == "Alto").sum())),
                cves_medios=("severidad_discreta", lambda s: int((s == "Medio").sum())),
                cves_bajos=("severidad_discreta", lambda s: int((s == "Bajo").sum())),
                cvss_promedio=("cvss_base", "mean"),
                cvss_max=("cvss_base", "max"),
                conteo_kev=("en_kev", lambda s: int(s.sum())),
                conteo_ransomware=("ransomware", lambda s: int((s == "Known").sum())),
            )
            .reset_index()
        )
        gold = malla.merge(agg_nvd, on=["grupo", "periodo"], how="left")
    else:
        gold = malla.copy()
        for col in [
            "total_cves",
            "cves_criticos",
            "cves_altos",
            "cves_medios",
            "cves_bajos",
            "cvss_promedio",
            "cvss_max",
            "conteo_kev",
            "conteo_ransomware",
        ]:
            gold[col] = 0

    for col in [
        "total_cves",
        "cves_criticos",
        "cves_altos",
        "cves_medios",
        "cves_bajos",
        "conteo_kev",
        "conteo_ransomware",
    ]:
        gold[col] = gold[col].fillna(0).astype(int)

    gold["cvss_promedio"] = gold["cvss_promedio"].fillna(0.0).round(2)
    gold["cvss_max"] = gold["cvss_max"].fillna(0.0).round(2)

    # Conteo KEV por catálogo histórico (dateAdded dentro de la ventana temporal)
    if df_kev_catalogo is not None and not df_kev_catalogo.empty:
        filas_kev = []
        for _, r in df_kev_catalogo.iterrows():
            per = str(r.get("periodo_kev", ""))
            for g in str(r.get("grupo_keyword_kev", "")).split(","):
                g = g.strip()
                if g in grupos_validos and per in periodos:
                    filas_kev.append((g, per))
        if filas_kev:
            kev_agg = (
                pd.DataFrame(filas_kev, columns=["grupo", "periodo"])
                .groupby(["grupo", "periodo"])
                .size()
                .reset_index(name="conteo_kev_catalogo")
            )
            gold = gold.merge(kev_agg, on=["grupo", "periodo"], how="left")
            gold["conteo_kev_catalogo"] = gold["conteo_kev_catalogo"].fillna(0).astype(int)
        else:
            gold["conteo_kev_catalogo"] = 0
    else:
        gold["conteo_kev_catalogo"] = gold["conteo_kev"]

    # Jerarquías conceptuales: tecnológica y temporal
    gold["macro_categoria"] = gold["grupo"].map(MACRO_CATEGORIA_POR_GRUPO)
    gold["anio"] = gold["periodo"].str.slice(0, 4).astype(int)
    gold["mes_num"] = gold["periodo"].str.slice(5, 7).astype(int)
    gold["trimestre"] = "Q" + (((gold["mes_num"] - 1) // 3) + 1).astype(str)

    # Detección y tratamiento de atípicos + normalización por grupo
    gold = gold.sort_values(["grupo", "periodo"]).reset_index(drop=True)
    tratados, flags_iqr, flags_mad = [], [], []
    for _, sub in gold.groupby("grupo", sort=False):
        t, iqr_m, mad_m = _tratar_atipicos_grupo(sub["total_cves"])
        tratados.append(t)
        flags_iqr.append(iqr_m)
        flags_mad.append(mad_m)

    gold["total_cves_tratado"] = pd.concat(tratados).sort_index()
    gold["es_atipico_iqr"] = pd.concat(flags_iqr).sort_index()
    gold["es_atipico_mad"] = pd.concat(flags_mad).sort_index()

    gold["total_cves_minmax"] = gold.groupby("grupo")["total_cves"].transform(_minmax_seguro)
    gold["cvss_promedio_minmax"] = gold.groupby("grupo")["cvss_promedio"].transform(_minmax_seguro)
    gold["total_cves_zscore"] = gold.groupby("grupo")["total_cves"].transform(_zscore_seguro)
    gold["cvss_promedio_zscore"] = gold.groupby("grupo")["cvss_promedio"].transform(_zscore_seguro)

    gold["nivel_riesgo_mensual"] = gold.apply(_discretizar_riesgo_mensual, axis=1)

    return esquema_gold(grupos_validos).validate(gold, lazy=True)


def ejecutar_pipeline_gold(
    carpeta_silver: Path | None = None,
    carpeta_gold: Path | None = None,
) -> dict:
    """Lee Silver, construye Gold (completo y reducido) y escribe metadatos."""
    cfg = cargar_grupos()
    grupos_validos = list(cfg["grupos"].keys())
    desde_periodo = cfg["desde"][:7]

    silver_dir = carpeta_silver or (RAIZ / "data" / "silver")
    gold_dir = carpeta_gold or (RAIZ / "data" / "gold")
    gold_dir.mkdir(parents=True, exist_ok=True)

    df_silver = pd.read_csv(silver_dir / "vulnerabilidades.csv")
    ruta_kev_cat = silver_dir / "kev_historico_catalogo.csv"
    df_kev_cat = pd.read_csv(ruta_kev_cat) if ruta_kev_cat.exists() else None

    gold = construir_series_gold(
        df_silver, grupos_validos, desde_periodo=desde_periodo, df_kev_catalogo=df_kev_cat
    )
    ruta_gold = gold_dir / "series_mensuales.csv"
    gold.to_csv(ruta_gold, index=False, encoding="utf-8")

    # Reducción de dimensionalidad / selección de variables para modelado E2
    gold_reducido = gold[COLUMNAS_REDUCIDAS].copy()
    ruta_reducida = gold_dir / "series_modelo.csv"
    gold_reducido.to_csv(ruta_reducida, index=False, encoding="utf-8")

    resumen = {
        "ingestado_utc": utcnow().isoformat(),
        "filas_gold": len(gold),
        "periodos_por_grupo": int(gold.groupby("grupo")["periodo"].nunique().min()),
        "atipicos_iqr_detectados": int(gold["es_atipico_iqr"].sum()),
        "atipicos_mad_detectados": int(gold["es_atipico_mad"].sum()),
        "columnas_completas": len(gold.columns),
        "columnas_reducidas": len(gold_reducido.columns),
        "sha256_gold": hashlib.sha256(ruta_gold.read_bytes()).hexdigest(),
        "sha256_modelo": hashlib.sha256(ruta_reducida.read_bytes()).hexdigest(),
    }
    (gold_dir / "series_mensuales.csv.meta.json").write_text(
        json.dumps(resumen, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return resumen


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Pipeline Silver -> Gold (series mensuales).")
    ap.add_argument("--silver", default=str(RAIZ / "data" / "silver"))
    ap.add_argument("--gold", default=str(RAIZ / "data" / "gold"))
    args = ap.parse_args(argv)

    resumen = ejecutar_pipeline_gold(Path(args.silver), Path(args.gold))
    print(
        f"Gold listo: {resumen['filas_gold']} filas ({resumen['periodos_por_grupo']} periodos/grupo, "
        f"atipicos IQR={resumen['atipicos_iqr_detectados']}, MAD={resumen['atipicos_mad_detectados']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
