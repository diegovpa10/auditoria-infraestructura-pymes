"""Pipeline Capa Silver: integración NVD + KEV, diagnóstico MCAR/MAR/MNAR,
imputación justificada, puerta de calidad con Pandera y cuarentena.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "bronze"))
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "silver"))

from common import RAIZ, cargar_grupos, coincide, leer_raw, utcnow  # noqa: E402
from calidad import (  # noqa: E402
    MACRO_CATEGORIA_POR_GRUPO,
    esquema_kev,
    esquema_pre_limpieza,
    esquema_silver,
    validar_con_cuarentena,
)


def _extraer_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """Resuelve jerarquía de versiones CVSS: v3.1 -> v3.0 -> v2.0."""
    for clave, ver, vec_key in (
        ("cvssMetricV31", "3.1", "attackVector"),
        ("cvssMetricV30", "3.0", "attackVector"),
        ("cvssMetricV2", "2.0", "accessVector"),
    ):
        lista = metrics.get(clave, [])
        if lista:
            data = lista[0].get("cvssData", {})
            return data.get("baseScore"), ver, data.get(vec_key)
    return None, None, None


def extraer_nvd_crudo(carpeta_nvd: Path, grupos: dict) -> pd.DataFrame:
    """Lee archivos Bronze de NVD y aplana el JSON anidado."""
    filas = []
    for grupo in grupos:
        dir_grupo = carpeta_nvd / grupo
        if not dir_grupo.exists():
            continue
        for archivo in sorted(dir_grupo.glob("*.json.gz")):
            keyword_origen = archivo.name.split("_")[0]
            for pagina in leer_raw(archivo):
                for item in pagina.get("respuesta", {}).get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    score, ver, vector = _extraer_cvss(cve.get("metrics", {}))
                    descs = [
                        d.get("value", "")
                        for d in cve.get("descriptions", [])
                        if d.get("lang") == "en"
                    ]
                    if not descs and cve.get("descriptions"):
                        descs = [cve["descriptions"][0].get("value", "")]
                    cwes = [
                        d.get("value")
                        for w in cve.get("weaknesses", [])
                        for d in w.get("description", [])
                        if d.get("value")
                    ]
                    filas.append(
                        {
                            "cve_id": cve.get("id"),
                            "grupo": grupo,
                            "keyword_origen": keyword_origen,
                            "vuln_status": cve.get("vulnStatus"),
                            "published_raw": cve.get("published"),
                            "last_modified_raw": cve.get("lastModified"),
                            "cvss_base_raw": score,
                            "cvss_version": ver,
                            "attack_vector": vector,
                            "cwe_principal": cwes[0] if cwes else None,
                            "num_refs": len(cve.get("references", [])),
                            "descripcion": descs[0].strip() if descs else "",
                        }
                    )
    return pd.DataFrame(filas)


def extraer_kev_crudo(carpeta_kev: Path, grupos: dict) -> pd.DataFrame:
    """Lee el último snapshot KEV de Bronze y homologa sus columnas base."""
    archivos = sorted(carpeta_kev.glob("kev_*.json.gz"))
    if not archivos:
        return pd.DataFrame(
            columns=[
                "cve_id",
                "kev_date_added_raw",
                "kev_due_date_raw",
                "ransomware",
                "vendor_project",
                "product",
                "kev_cwes",
                "grupo_keyword_kev",
            ]
        )
    datos = leer_raw(archivos[-1])
    filas = []
    for v in datos.get("vulnerabilities", []):
        texto = f"{v.get('vendorProject', '')} {v.get('product', '')}"
        grupos_match = [g for g, info in grupos.items() if coincide(texto, info["keywords"])]
        filas.append(
            {
                "cve_id": v.get("cveID"),
                "kev_date_added_raw": v.get("dateAdded"),
                "kev_due_date_raw": v.get("dueDate"),
                "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                "vendor_project": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "kev_cwes": ",".join(v.get("cwes", [])),
                "grupo_keyword_kev": ",".join(grupos_match) if grupos_match else None,
            }
        )
    return pd.DataFrame(filas)


def diagnosticar_faltantes(df: pd.DataFrame) -> dict:
    """Diagnostica el mecanismo de valores faltantes (MCAR/MAR/MNAR) en `cvss_base`."""
    total = len(df)
    n_faltantes = int(df["cvss_base"].isna().sum())
    pct_faltantes = round((n_faltantes / total * 100.0) if total else 0.0, 2)

    diag = {
        "total_registros": total,
        "faltantes_cvss": n_faltantes,
        "porcentaje_faltantes_cvss": pct_faltantes,
        "faltantes_attack_vector": int(df["attack_vector"].isna().sum()),
        "faltantes_cwe": int(df["cwe_principal"].isna().sum()),
        "mecanismo_diagnosticado": "Sin faltantes",
        "chi2_stat": None,
        "chi2_pvalue": None,
        "detalle_por_status": {},
    }
    if n_faltantes == 0 or total == 0:
        return diag

    tabla = pd.crosstab(df["vuln_status"], df["cvss_base"].isna())
    diag["detalle_por_status"] = {
        str(k): int(v) for k, v in df[df["cvss_base"].isna()]["vuln_status"].value_counts().items()
    }
    if tabla.shape[0] >= 2 and tabla.shape[1] == 2:
        chi2, p_val, _, _ = stats.chi2_contingency(tabla)
        diag["chi2_stat"] = round(float(chi2), 4)
        diag["chi2_pvalue"] = float(p_val)
        diag["mecanismo_diagnosticado"] = (
            "MAR (dependiente de vuln_status)" if p_val < 0.05 else "MCAR (independiente de vuln_status)"
        )
    else:
        diag["mecanismo_diagnosticado"] = "MAR (concentrado en un único estado)"
    return diag


def _detectar_atipicos_iqr_mad(serie: pd.Series) -> tuple[pd.Series, pd.Series]:
    """Retorna máscaras booleanas de valores atípicos por IQR y Z-Score robusto (MAD)."""
    q1, q3 = serie.quantile(0.25), serie.quantile(0.75)
    iqr = q3 - q1
    if iqr > 0:
        lim_sup = q3 + 1.5 * iqr
        lim_inf = q1 - 1.5 * iqr
        mask_iqr = (serie > lim_sup) | (serie < lim_inf)
    else:
        mask_iqr = pd.Series(False, index=serie.index)

    med = serie.median()
    mad = (serie - med).abs().median()
    if mad > 0:
        z_rob = 0.6745 * (serie - med) / mad
        mask_mad = z_rob.abs() > 3.5
    else:
        mask_mad = pd.Series(False, index=serie.index)
    return mask_iqr, mask_mad


def discretizar_cvss(score: float) -> str:
    """Discretiza puntuación CVSS (0-10) en niveles estándar de severidad."""
    if score >= 9.0:
        return "Critico"
    if score >= 7.0:
        return "Alto"
    if score >= 4.0:
        return "Medio"
    return "Bajo"


def _parsear_nvd_con_cuarentena(df_raw: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Convierte tipos de NVD capturando errores de parseo en cuarentena sin perder filas."""
    df = df_raw.copy()
    df["published"] = pd.to_datetime(df["published_raw"], errors="coerce").dt.tz_localize(None)
    df["last_modified"] = pd.to_datetime(df["last_modified_raw"], errors="coerce").dt.tz_localize(None)
    df["cvss_base"] = pd.to_numeric(df["cvss_base_raw"], errors="coerce")

    fallo_pub = df["published"].isna()
    fallo_mod = df["last_modified"].isna()
    fallo_cvss = df["cvss_base_raw"].notna() & df["cvss_base"].isna()
    mask_error = fallo_pub | fallo_mod | fallo_cvss

    if not mask_error.any():
        return df, df.iloc[0:0].copy()

    motivos = []
    for idx in df.index[mask_error]:
        razones = []
        if fallo_pub.loc[idx]:
            razones.append(f"published inválido ({df.loc[idx, 'published_raw']})")
        if fallo_mod.loc[idx]:
            razones.append(f"last_modified inválido ({df.loc[idx, 'last_modified_raw']})")
        if fallo_cvss.loc[idx]:
            razones.append(f"cvss_base no numérico ({df.loc[idx, 'cvss_base_raw']})")
        motivos.append("; ".join(razones))

    cuarentena = df.loc[mask_error].copy()
    cuarentena["motivo_cuarentena"] = motivos
    cuarentena["etapa_puerta"] = "parseo_tipos"
    cuarentena["fecha_cuarentena_utc"] = utcnow().isoformat()
    return df.loc[~mask_error].copy(), cuarentena


def ejecutar_pipeline_silver(
    carpeta_bronze: Path | None = None,
    carpeta_silver: Path | None = None,
    carpeta_cuarentena: Path | None = None,
    df_nvd_inyectado: pd.DataFrame | None = None,
    df_kev_inyectado: pd.DataFrame | None = None,
) -> dict:
    """Ejecuta el pipeline completo Bronze -> Silver con puerta de calidad Pandera."""
    cfg = cargar_grupos()
    grupos = cfg["grupos"]
    grupos_validos = list(grupos.keys())

    bronze = carpeta_bronze or (RAIZ / "data" / "bronze")
    silver_dir = carpeta_silver or (RAIZ / "data" / "silver")
    cuarentena_dir = carpeta_cuarentena or (RAIZ / "data" / "cuarentena")
    silver_dir.mkdir(parents=True, exist_ok=True)
    cuarentena_dir.mkdir(parents=True, exist_ok=True)

    # 1. Extracción cruda
    nvd_raw = df_nvd_inyectado.copy() if df_nvd_inyectado is not None else extraer_nvd_crudo(bronze / "nvd", grupos)
    kev_raw = df_kev_inyectado.copy() if df_kev_inyectado is not None else extraer_kev_crudo(bronze / "kev", grupos)
    total_nvd_crudo = len(nvd_raw)

    cuarentenas: list[pd.DataFrame] = []

    # 2. Parseo seguro de tipos y deduplicación NVD
    nvd_parsed, cuar_parseo = _parsear_nvd_con_cuarentena(nvd_raw)
    if not cuar_parseo.empty:
        cuarentenas.append(cuar_parseo)

    nvd_parsed = nvd_parsed.sort_values("last_modified", ascending=False)
    nvd_dedup = nvd_parsed.drop_duplicates(subset=["grupo", "cve_id"], keep="first").copy()
    duplicados_removidos = len(nvd_parsed) - len(nvd_dedup)

    # 3. Validación y preparación de KEV
    if not kev_raw.empty:
        kev_work = kev_raw.copy()
        kev_work["kev_date_added"] = pd.to_datetime(kev_work["kev_date_added_raw"], errors="coerce").dt.tz_localize(None)
        kev_work["kev_due_date"] = pd.to_datetime(kev_work["kev_due_date_raw"], errors="coerce").dt.tz_localize(None)
        kev_valid, cuar_kev = validar_con_cuarentena(kev_work, esquema_kev(), etapa="validacion_kev")
        if not cuar_kev.empty:
            cuarentenas.append(cuar_kev)
        kev_valid = kev_valid.drop_duplicates(subset=["cve_id"], keep="first")
    else:
        kev_valid = pd.DataFrame(
            {
                "cve_id": pd.Series(dtype="object"),
                "kev_date_added": pd.Series(dtype="datetime64[ns]"),
                "kev_due_date": pd.Series(dtype="datetime64[ns]"),
                "ransomware": pd.Series(dtype="object"),
                "vendor_project": pd.Series(dtype="object"),
                "product": pd.Series(dtype="object"),
                "grupo_keyword_kev": pd.Series(dtype="object"),
            }
        )

    # 4. Integración y resolución de conflictos de esquema (NVD + KEV)
    integrado = nvd_dedup.merge(
        kev_valid[["cve_id", "kev_date_added", "kev_due_date", "ransomware", "vendor_project", "product"]],
        on="cve_id",
        how="left",
    )
    integrado["kev_date_added"] = pd.to_datetime(integrado["kev_date_added"], errors="coerce")
    integrado["en_kev"] = integrado["kev_date_added"].notna()
    integrado["ransomware"] = integrado["ransomware"].fillna("No_KEV")
    if integrado["en_kev"].any():
        integrado["dias_a_kev"] = np.where(
            integrado["en_kev"],
            (integrado["kev_date_added"] - integrado["published"].dt.normalize()).dt.days.astype(float),
            np.nan,
        )
    else:
        integrado["dias_a_kev"] = np.nan

    # 5. Puerta de Calidad Pre-Imputación (Pandera) -> envía inválidos a cuarentena
    integrado_ok, cuar_pre = validar_con_cuarentena(
        integrado, esquema_pre_limpieza(grupos_validos), etapa="puerta_pre_limpieza"
    )
    if not cuar_pre.empty:
        cuarentenas.append(cuar_pre)

    # 6. Diagnóstico estadístico de valores faltantes (MCAR/MAR/MNAR)
    diag_faltantes = diagnosticar_faltantes(integrado_ok)

    # 7. Imputación justificada
    df_silver = integrado_ok.copy()
    df_silver["cvss_imputado"] = df_silver["cvss_base"].isna()
    medianas_grupo = df_silver.groupby("grupo")["cvss_base"].transform("median")
    mediana_global = float(df_silver["cvss_base"].median()) if df_silver["cvss_base"].notna().any() else 5.0
    df_silver["cvss_base"] = df_silver["cvss_base"].fillna(medianas_grupo).fillna(mediana_global).round(1)
    df_silver["cvss_version"] = df_silver["cvss_version"].fillna("IMPUTADO")
    df_silver["attack_vector"] = df_silver["attack_vector"].fillna("DESCONOCIDO")
    df_silver["cwe_principal"] = df_silver["cwe_principal"].fillna("SIN_CWE")

    # 8. Detección de atípicos a nivel CVE y enriquecimiento conceptual
    df_silver["dias_modificacion"] = (
        (df_silver["last_modified"] - df_silver["published"]).dt.total_seconds() / 86400.0
    ).round(2)
    df_silver["es_atipico_refs"], _ = _detectar_atipicos_iqr_mad(df_silver["num_refs"])
    _, df_silver["es_atipico_mod"] = _detectar_atipicos_iqr_mad(df_silver["dias_modificacion"])

    df_silver["severidad_discreta"] = df_silver["cvss_base"].apply(discretizar_cvss)
    df_silver["macro_categoria"] = df_silver["grupo"].map(MACRO_CATEGORIA_POR_GRUPO)
    df_silver["periodo"] = df_silver["published"].dt.to_period("M").astype(str)

    columnas_silver = [
        "cve_id",
        "grupo",
        "macro_categoria",
        "keyword_origen",
        "vuln_status",
        "published",
        "last_modified",
        "periodo",
        "dias_modificacion",
        "cvss_base",
        "cvss_imputado",
        "cvss_version",
        "severidad_discreta",
        "attack_vector",
        "cwe_principal",
        "num_refs",
        "es_atipico_refs",
        "es_atipico_mod",
        "en_kev",
        "kev_date_added",
        "ransomware",
        "dias_a_kev",
        "descripcion",
    ]
    df_silver = df_silver[columnas_silver].sort_values(["published", "grupo", "cve_id"]).reset_index(drop=True)

    # 9. Puerta de Calidad Final Estricto (Pandera Silver)
    df_silver, cuar_post = validar_con_cuarentena(
        df_silver, esquema_silver(grupos_validos), etapa="puerta_silver_final"
    )
    if not cuar_post.empty:
        cuarentenas.append(cuar_post)

    # 10. Guardar salidas Silver, KEV histórico por palabras clave y Cuarentena
    ruta_silver = silver_dir / "vulnerabilidades.csv"
    df_silver.to_csv(ruta_silver, index=False, encoding="utf-8")

    # Tabla auxiliar de KEV coincidente por keywords (incluye CVEs pre-2021 que siguen activos)
    if not kev_valid.empty and "grupo_keyword_kev" in kev_valid.columns:
        kev_kw = kev_valid[kev_valid["grupo_keyword_kev"].notna()].copy()
        kev_kw["periodo_kev"] = kev_kw["kev_date_added"].dt.to_period("M").astype(str)
        kev_kw.to_csv(silver_dir / "kev_historico_catalogo.csv", index=False, encoding="utf-8")

    ruta_cuarentena = cuarentena_dir / "cuarentena_silver.csv"
    if cuarentenas:
        df_cuarentena = pd.concat(cuarentenas, ignore_index=True)
    else:
        df_cuarentena = pd.DataFrame(
            columns=["cve_id", "grupo", "vuln_status", "motivo_cuarentena", "etapa_puerta", "fecha_cuarentena_utc"]
        )
    df_cuarentena.to_csv(ruta_cuarentena, index=False, encoding="utf-8")

    contenido_bytes = ruta_silver.read_bytes()
    resumen = {
        "ingestado_utc": utcnow().isoformat(),
        "registros_nvd_crudos": total_nvd_crudo,
        "duplicados_keyword_eliminados": duplicados_removidos,
        "registros_silver_validos": len(df_silver),
        "registros_cuarentena": len(df_cuarentena),
        "coincidencias_nvd_kev": int(df_silver["en_kev"].sum()) if not df_silver.empty else 0,
        "diagnostico_faltantes": diag_faltantes,
        "sha256_silver": hashlib.sha256(contenido_bytes).hexdigest(),
    }
    (silver_dir / "vulnerabilidades.csv.meta.json").write_text(
        json.dumps(resumen, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return resumen


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Pipeline de limpieza Bronze -> Silver con Pandera.")
    ap.add_argument("--bronze", default=str(RAIZ / "data" / "bronze"))
    ap.add_argument("--silver", default=str(RAIZ / "data" / "silver"))
    ap.add_argument("--cuarentena", default=str(RAIZ / "data" / "cuarentena"))
    args = ap.parse_args(argv)

    resumen = ejecutar_pipeline_silver(
        Path(args.bronze), Path(args.silver), Path(args.cuarentena)
    )
    print(
        f"Silver listo: {resumen['registros_silver_validos']} validos "
        f"({resumen['duplicados_keyword_eliminados']} duplicados removidos, "
        f"{resumen['registros_cuarentena']} en cuarentena, "
        f"diagnostico CVSS={resumen['diagnostico_faltantes']['mecanismo_diagnosticado']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
