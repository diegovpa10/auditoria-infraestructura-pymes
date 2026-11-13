# Ficha Técnica de Entrega E1 · Capas Plata, Oro y Puerta de Calidad

**Proyecto:** Observatorio de exposición digital de pymes de distribución (Colima)  
**Equipo:** Diego Vargas  
**Fecha:** 2026-11-12  
**Etiqueta objetivo:** `e1`

---

## 1. Inventario de Entregables

| Requisito E1 | Implementación en el repositorio | Descripción |
|---|---|---|
| Pipeline de limpieza y preprocesamiento | [src/silver/limpieza.py](../../src/silver/limpieza.py), [src/gold/series.py](../../src/gold/series.py) y [docs/E1/limpieza.ipynb](limpieza.ipynb) | Diagnóstico MCAR/MAR/MNAR, imputación, atípicos (IQR y MAD), normalización Min-Max/Z-Score, discretización, jerarquías conceptuales y reducción. |
| Integración y resolución de conflictos | [src/silver/limpieza.py](../../src/silver/limpieza.py) | Fusión NVD API 2.0 + CISA KEV resolviendo nombres de columnas, formatos de fecha, CVSS multinivel (`3.1 → 3.0 → 2.0`) y duplicados por palabras clave. |
| Puerta de Calidad Automática + Cuarentena | [src/silver/calidad.py](../../src/silver/calidad.py) | Validación estricta con **Pandera** (`lazy=True`) en tres etapas (`esquema_kev`, `esquema_pre_limpieza`, `esquema_silver`) y esquema Gold (`esquema_gold`). Envío explícito de inválidos a `data/cuarentena/cuarentena_silver.csv`. |
| Automatización CI/CD | [.github/workflows/extraer.yml](../../.github/workflows/extraer.yml) | El workflow semanal/manual ejecuta pruebas unitarias, extracción Bronze, pipeline Silver (con puerta Pandera) y pipeline Gold, guardando salidas y metadatos en `data/`. |
| Pruebas automatizadas | [tests/test_silver_gold.py](../../tests/test_silver_gold.py) | Verificación de deduplicación, imputación, integración KEV, detección de atípicos y envío a cuarentena de registros corruptos inyectados. |
| Documentación de etapa | `docs/E1/ENTREGA.md` y [docs/relatoria-E1.md](../relatoria-E1.md) | Ficha técnica y relatoría de decisiones, hallazgos y lecciones aprendidas. |

---

## 2. Métricas Reales Obtenidas en Ejecución

- **NVD Bronze leído:** 1,844 registros crudos → **42 duplicados** entre palabras clave eliminados → **1,802 CVEs únicos** por `(grupo, cve_id)`.
- **Mecanismo de faltantes (`cvss_base`):** 69 faltantes tras jerarquía v3.1→v3.0→v2.0 (3.83 %), concentrados en `Deferred` (55), `Awaiting Analysis` (13) y `Received` (1). Prueba $\chi^2 = 469.56$ ($p = 2.56 \times 10^{-100} < 0.05$) → **MAR (Missing At Random)**.
- **Integración NVD–KEV:** 18 coincidencias directas por `cve_id` en el rango 2021-11+; 41 entradas KEV por palabras clave preservadas en `data/silver/kev_historico_catalogo.csv`.
- **Puerta de Calidad (datos reales):** 1,802 válidos en `data/silver/vulnerabilidades.csv`, 0 inválidos en `data/cuarentena/cuarentena_silver.csv` (mecanismo de cuarentena validado con registros sintéticos inválidos en `tests/test_silver_gold.py` y `docs/E1/limpieza.ipynb`).
- **Capa Gold (`data/gold/series_mensuales.csv`):** 366 filas (6 grupos $\times$ 61 periodos contiguos `2021-11` a `2026-11`), 24 variables completas; 22 meses atípicos detectados por IQR y 13 por Z-Score robusto (MAD).
- **Reducción de datos (`data/gold/series_modelo.csv`):** Selección de 13 variables ortogonales para modelado predictivo en E2.

---

## 3. Lista de Cotejo Pre-Tag `e1`

- [x] Pipeline Silver, Puerta de Calidad Pandera y Pipeline Gold implementados y ejecutados.
- [x] Notebook [docs/E1/limpieza.ipynb](limpieza.ipynb) ejecutado con gráficas y salidas estadísticas guardadas.
- [x] Pruebas unitarias pasando (`python -m unittest discover -s tests`: 11/11 OK).
- [x] Workflow `.github/workflows/extraer.yml` actualizado para automatizar Bronze → Silver → Gold.
- [x] Documentación `docs/E1/ENTREGA.md` y `docs/relatoria-E1.md` creada.
- [x] Actualizar registro PSP en `calidad/tiempo-diego.csv` y `calidad/defectos-diego.csv`.
- [x] Verificar en GitHub Actions que el workflow actualizado corre en verde.
- [x] Crear etiqueta `git tag e1 && git push origin e1` y registrar enlace en el formulario oficial.
