"""Puerta de Calidad Automática con Pandera y envío a cuarentena de registros inválidos."""
from __future__ import annotations

from datetime import datetime, timezone
import pandas as pd
import pandera.pandas as pa
from pandera.errors import SchemaErrors

ESTADOS_VALIDOS = {
    "Analyzed",
    "Modified",
    "Deferred",
    "Awaiting Analysis",
    "Received",
    "Undergoing Analysis",
}

MACRO_CATEGORIA_POR_GRUPO = {
    "modems_red": "Infraestructura_Red",
    "camaras_ip": "Infraestructura_Red",
    "windows_office": "Puesto_Trabajo",
    "impresoras_hp": "Puesto_Trabajo",
    "contpaqi": "Operacion_Negocio",
    "soporte_remoto": "Operacion_Negocio",
}


def esquema_kev() -> pa.DataFrameSchema:
    """Esquema de validación para el catálogo CISA KEV antes de integrarlo."""
    return pa.DataFrameSchema(
        columns={
            "cve_id": pa.Column(
                str,
                pa.Check.str_matches(r"^CVE-\d{4}-\d{4,}$"),
                nullable=False,
            ),
            "kev_date_added": pa.Column("datetime64[ns]", nullable=False),
            "kev_due_date": pa.Column("datetime64[ns]", nullable=True),
            "ransomware": pa.Column(
                str,
                pa.Check.isin(["Known", "Unknown"]),
                nullable=False,
            ),
            "vendor_project": pa.Column(str, nullable=False),
            "product": pa.Column(str, nullable=False),
        },
        checks=[
            pa.Check(
                lambda d: d["kev_due_date"].isna() | (d["kev_due_date"] >= d["kev_date_added"]),
                name="kev_due_date_posterior",
            )
        ],
        coerce=True,
    )


def esquema_pre_limpieza(grupos_validos: list[str]) -> pa.DataFrameSchema:
    """Esquema estructural y de dominio previo a la imputación de valores faltantes."""
    limite_superior = pd.Timestamp.now("UTC").tz_localize(None) + pd.Timedelta(days=2)
    return pa.DataFrameSchema(
        columns={
            "cve_id": pa.Column(
                str,
                pa.Check.str_matches(r"^CVE-\d{4}-\d{4,}$"),
                nullable=False,
            ),
            "grupo": pa.Column(str, pa.Check.isin(grupos_validos), nullable=False),
            "vuln_status": pa.Column(str, pa.Check.isin(ESTADOS_VALIDOS), nullable=False),
            "published": pa.Column(
                "datetime64[ns]",
                [
                    pa.Check.ge(pd.Timestamp("2021-11-01")),
                    pa.Check.le(limite_superior),
                ],
                nullable=False,
            ),
            "last_modified": pa.Column("datetime64[ns]", nullable=False),
            "cvss_base": pa.Column(
                float,
                pa.Check.in_range(0.0, 10.0),
                nullable=True,
            ),
            "num_refs": pa.Column(int, pa.Check.ge(0), nullable=False),
            "descripcion": pa.Column(
                str,
                pa.Check.str_length(min_value=5),
                nullable=False,
            ),
            "en_kev": pa.Column(bool, nullable=False),
            "dias_a_kev": pa.Column(
                float,
                pa.Check.ge(0.0),
                nullable=True,
            ),
        },
        checks=[
            pa.Check(
                lambda d: d["last_modified"] >= d["published"],
                name="fechas_coherentes_nvd",
            ),
            pa.Check(
                lambda d: (~d["en_kev"]) | d["kev_date_added"].notna(),
                name="kev_fecha_presente",
            ),
        ],
        coerce=True,
    )


def esquema_silver(grupos_validos: list[str]) -> pa.DataFrameSchema:
    """Esquema estricto de la Capa Plata (sin nulos en campos críticos y rangos cerrados)."""
    return pa.DataFrameSchema(
        columns={
            "cve_id": pa.Column(
                str,
                pa.Check.str_matches(r"^CVE-\d{4}-\d{4,}$"),
                nullable=False,
            ),
            "grupo": pa.Column(str, pa.Check.isin(grupos_validos), nullable=False),
            "macro_categoria": pa.Column(
                str,
                pa.Check.isin(set(MACRO_CATEGORIA_POR_GRUPO.values())),
                nullable=False,
            ),
            "vuln_status": pa.Column(str, pa.Check.isin(ESTADOS_VALIDOS), nullable=False),
            "published": pa.Column("datetime64[ns]", nullable=False),
            "last_modified": pa.Column("datetime64[ns]", nullable=False),
            "periodo": pa.Column(str, pa.Check.str_matches(r"^\d{4}-\d{2}$"), nullable=False),
            "cvss_base": pa.Column(float, pa.Check.in_range(0.0, 10.0), nullable=False),
            "cvss_imputado": pa.Column(bool, nullable=False),
            "cvss_version": pa.Column(
                str,
                pa.Check.isin(["3.1", "3.0", "2.0", "IMPUTADO"]),
                nullable=False,
            ),
            "severidad_discreta": pa.Column(
                str,
                pa.Check.isin(["Bajo", "Medio", "Alto", "Critico"]),
                nullable=False,
            ),
            "attack_vector": pa.Column(
                str,
                pa.Check.isin(["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL", "DESCONOCIDO"]),
                nullable=False,
            ),
            "cwe_principal": pa.Column(str, pa.Check.str_length(min_value=3), nullable=False),
            "num_refs": pa.Column(int, pa.Check.ge(0), nullable=False),
            "en_kev": pa.Column(bool, nullable=False),
            "ransomware": pa.Column(
                str,
                pa.Check.isin(["Known", "Unknown", "No_KEV"]),
                nullable=False,
            ),
            "dias_a_kev": pa.Column(float, pa.Check.ge(0.0), nullable=True),
        },
        unique=["grupo", "cve_id"],
        checks=[
            pa.Check(
                lambda d: d["last_modified"] >= d["published"],
                name="fechas_coherentes_silver",
            ),
        ],
        coerce=True,
    )


def esquema_gold(grupos_validos: list[str]) -> pa.DataFrameSchema:
    """Esquema estricto de la Capa Oro (series mensuales listas para pronóstico)."""
    return pa.DataFrameSchema(
        columns={
            "grupo": pa.Column(str, pa.Check.isin(grupos_validos), nullable=False),
            "macro_categoria": pa.Column(
                str,
                pa.Check.isin(set(MACRO_CATEGORIA_POR_GRUPO.values())),
                nullable=False,
            ),
            "periodo": pa.Column(str, pa.Check.str_matches(r"^\d{4}-\d{2}$"), nullable=False),
            "anio": pa.Column(int, pa.Check.ge(2021), nullable=False),
            "trimestre": pa.Column(str, pa.Check.isin(["Q1", "Q2", "Q3", "Q4"]), nullable=False),
            "mes_num": pa.Column(int, pa.Check.in_range(1, 12), nullable=False),
            "total_cves": pa.Column(int, pa.Check.ge(0), nullable=False),
            "total_cves_tratado": pa.Column(float, pa.Check.ge(0.0), nullable=False),
            "cves_criticos": pa.Column(int, pa.Check.ge(0), nullable=False),
            "cves_altos": pa.Column(int, pa.Check.ge(0), nullable=False),
            "cves_medios": pa.Column(int, pa.Check.ge(0), nullable=False),
            "cves_bajos": pa.Column(int, pa.Check.ge(0), nullable=False),
            "cvss_promedio": pa.Column(float, pa.Check.in_range(0.0, 10.0), nullable=False),
            "cvss_max": pa.Column(float, pa.Check.in_range(0.0, 10.0), nullable=False),
            "conteo_kev": pa.Column(int, pa.Check.ge(0), nullable=False),
            "conteo_kev_catalogo": pa.Column(int, pa.Check.ge(0), nullable=False),
            "conteo_ransomware": pa.Column(int, pa.Check.ge(0), nullable=False),
            "total_cves_minmax": pa.Column(float, pa.Check.in_range(0.0, 1.0), nullable=False),
            "cvss_promedio_minmax": pa.Column(float, pa.Check.in_range(0.0, 1.0), nullable=False),
            "total_cves_zscore": pa.Column(float, nullable=False),
            "cvss_promedio_zscore": pa.Column(float, nullable=False),
            "es_atipico_iqr": pa.Column(bool, nullable=False),
            "es_atipico_mad": pa.Column(bool, nullable=False),
            "nivel_riesgo_mensual": pa.Column(
                str,
                pa.Check.isin(["Sin_Exposicion", "Bajo", "Medio", "Alto", "Critico"]),
                nullable=False,
            ),
        },
        unique=["grupo", "periodo"],
        coerce=True,
    )


def _construir_motivos(failure_cases: pd.DataFrame) -> dict:
    """Agrupa fallos de Pandera por índice de fila en mensajes legibles y sin duplicados."""
    motivos: dict = {}
    if failure_cases.empty:
        return motivos

    vistos: dict = {}
    for _, row in failure_cases.iterrows():
        idx = row.get("index")
        if pd.isna(idx):
            continue
        col = str(row.get("column") or "dataframe")
        chk = str(row.get("check") or "regla")
        val = row.get("failure_case")
        # Para checks a nivel DataFrame, evitar repetir el mismo check por cada columna
        clave_dedup = (idx, chk) if chk in {
            "fechas_coherentes_nvd",
            "kev_fecha_presente",
            "fechas_coherentes_silver",
            "kev_due_date_posterior",
        } else (idx, col, chk)
        if clave_dedup in vistos.setdefault(idx, set()):
            continue
        vistos[idx].add(clave_dedup)
        detalle = f"{col}: {chk} (valor={val})"
        motivos.setdefault(idx, []).append(detalle)

    return {idx: "; ".join(lista) for idx, lista in motivos.items()}


def validar_con_cuarentena(
    df: pd.DataFrame,
    schema: pa.DataFrameSchema,
    etapa: str,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Valida `df` con Pandera (`lazy=True`).

    Los registros que fallan la validación se separan y retornan con su motivo
    documentado para envío a cuarentena (nunca se descartan en silencio).
    """
    if df.empty:
        cuarentena_vacia = df.copy()
        cuarentena_vacia["motivo_cuarentena"] = pd.Series(dtype="object")
        cuarentena_vacia["etapa_puerta"] = pd.Series(dtype="object")
        cuarentena_vacia["fecha_cuarentena_utc"] = pd.Series(dtype="object")
        return df.copy(), cuarentena_vacia

    trabajo = df.copy()
    try:
        validado = schema.validate(trabajo, lazy=True)
        cuarentena_vacia = trabajo.iloc[0:0].copy()
        cuarentena_vacia["motivo_cuarentena"] = pd.Series(dtype="object")
        cuarentena_vacia["etapa_puerta"] = pd.Series(dtype="object")
        cuarentena_vacia["fecha_cuarentena_utc"] = pd.Series(dtype="object")
        return validado, cuarentena_vacia
    except SchemaErrors as exc:
        motivos_por_idx = _construir_motivos(exc.failure_cases)
        indices_invalidos = [i for i in trabajo.index if i in motivos_por_idx]
        if not indices_invalidos:
            # Error global de esquema que no apunta a fila específica
            raise

        ahora_utc = datetime.now(timezone.utc).isoformat()
        cuarentena = trabajo.loc[indices_invalidos].copy()
        cuarentena["motivo_cuarentena"] = [motivos_por_idx[i] for i in indices_invalidos]
        cuarentena["etapa_puerta"] = etapa
        cuarentena["fecha_cuarentena_utc"] = ahora_utc

        validos = trabajo.drop(index=indices_invalidos).copy()
        if not validos.empty:
            validos = schema.validate(validos, lazy=True)
        return validos, cuarentena
