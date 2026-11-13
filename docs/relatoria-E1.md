# Relatoría de Etapa E1 · Limpieza Estadística, Integración y Puerta de Calidad

**Proyecto:** Observatorio de exposición digital de pymes de distribución (Colima)  
**Etapa:** E1 (Unidad 3)  
**Fecha:** 2026-11-12  

---

## 1. Propósito de la Etapa
Tras consolidar la extracción reproducible en la capa Bronze (E0), la etapa E1 tuvo como propósito transformar las respuestas JSON anidadas de **NVD API 2.0** y **CISA KEV** en conjuntos tabulares analíticos (**Capa Silver** y **Capa Gold**), asegurando rigor estadístico en el tratamiento de datos y evitando la pérdida silenciosa de información mediante una **Puerta de Calidad Automática con Pandera** y envío explícito a cuarentena.

---

## 2. Desafíos Encontrados y Decisiones de Diseño

### 2.1 Integración y Resolución de Conflictos de Esquema (NVD vs. KEV)
Al cruzar los datos reales de Bronze se detectaron cuatro conflictos estructurales principales:
1. **Duplicación por palabras clave:** Los 1,844 registros crudos de NVD incluían **42 duplicados** dentro del mismo grupo (por ejemplo, un mismo CVE devuelto tanto por `microsoft-office` como por `microsoft-365`, o `dvr` e `ip-camera`). Se resolvió deduplicando por `(grupo, cve_id)` y conservando el registro con fecha `lastModified` más reciente.
2. **Heterogeneidad en métricas CVSS:** NVD no entrega una única columna numérica, sino listas anidadas para versiones `v3.1`, `v3.0` y `v2.0` (con nombres de vector distintos: `attackVector` vs `accessVector`). Se aplicó una regla de prioridad descendente (`v3.1 → v3.0 → v2.0`), logrando rescatar 8 calificaciones que no estaban en `v3.1`.
3. **Formatos temporales e identificadores:** NVD utiliza timestamps ISO-8601 (`cve.id`, `published`, `lastModified`), mientras que KEV utiliza fechas simples `YYYY-MM-DD` (`cveID`, `dateAdded`, `dueDate`) y cadenas categóricas (`"Known"` / `"Unknown"`). Se homologaron todas las fechas a `datetime64[ns]` sin zona horaria y se enriqueció el resultado del `LEFT JOIN` con la variable derivada `dias_a_kev` y el valor `"No_KEV"` para CVEs no explotados activamente.
4. **Cobertura temporal NVD vs. KEV:** Aunque 18 CVEs coincidieron por `cve_id` con la ventana 2021-11+ de NVD, el catálogo KEV contiene 41 entradas asociadas por palabras clave a las tecnologías de la pyme (incluyendo vulnerabilidades previas a 2021 como Office 2017 o TeamViewer 2019). Para no perder esa señal histórica en la integración, se conservó el detalle auxiliar en `data/silver/kev_historico_catalogo.csv` y se incorporó la columna `conteo_kev_catalogo` en la capa Gold.

### 2.2 Diagnóstico Estadístico de Valores Faltantes (MAR) e Imputación
En los 1,802 CVEs únicos de NVD, **69 registros (3.83 %)** carecían por completo de puntuación CVSS tras la jerarquía de versiones. Para no imputar a ciegas, se realizó una tabla de contingencia y una prueba de independencia $\chi^2$ entre la ausencia de `cvss_base` y el estado `vuln_status`:
* **Distribución observada:** `Deferred` (55 faltantes), `Awaiting Analysis` (13), `Received` (1), frente a 0 faltantes en `Analyzed` y `Modified`.
* **Resultado estadístico:** $\chi^2 = 469.56$, $p = 2.56 \times 10^{-100} \ll 0.05$.
* **Decisión:** Se descartó MCAR y se diagnosticó formalmente un mecanismo **MAR (Missing At Random)** dependiente del estado de revisión del CVE. Se aplicó imputación mediante la **mediana del grupo tecnológico** (robusta ante distribuciones asimétricas de severidad) acompañada de la bandera de trazabilidad `cvss_imputado = True`. Las variables categóricas faltantes (`attack_vector` y `cwe_principal`) se imputaron explícitamente como `"DESCONOCIDO"` y `"SIN_CWE"`.

### 2.3 Puerta de Calidad con Pandera y Cuarentena Explícita
Se eligió **Pandera** (`pandera.pandas`) por su integración directa con `pandas`, validación en modo `lazy=True` y capacidad de reportar fallos fila por fila (`failure_cases`). Se implementaron cuatro esquemas (`esquema_kev`, `esquema_pre_limpieza`, `esquema_silver` y `esquema_gold`).
* Cualquier registro con `cve_id` malformado, `vuln_status == 'Rejected'`, CVSS fuera de `[0.0, 10.0]`, fechas corruptas o inconsistencias temporales (`last_modified < published` o `dias_a_kev < 0`) se desvía automáticamente a `data/cuarentena/cuarentena_silver.csv` registrando `motivo_cuarentena`, `etapa_puerta` y `fecha_cuarentena_utc`.
* En los datos reales descargados pasaron 1,802 registros y 0 fueron a cuarentena; el comportamiento de bloqueo y desvío se comprobó inyectando 5 casos sucios sintéticos en `tests/test_silver_gold.py` y en `docs/E1/limpieza.ipynb`.

### 2.4 Preprocesamiento hacia Capa Gold (Atípicos, Escalamiento, Discretización y Reducción)
Para dejar las series mensuales listas para pronóstico (E2):
* **Series contiguas:** Se construyó una malla completa de 61 meses (`2021-11` a `2026-11`) por grupo (366 filas), rellenando explícitamente los meses sin publicaciones (clave en `contpaqi`, que registra 60 meses en cero y 1 CVE aislado).
* **Atípicos:** Se detectaron **22 meses atípicos con IQR (Tukey)** y **13 con Z-Score robusto (MAD)** (destacando picos como 218 CVEs en un solo mes para `windows_office`). Para no distorsionar la realidad ni perder el dato crudo, se mantuvo `total_cves` intacto y se creó `total_cves_tratado` mediante winsorización al límite superior de Tukey.
* **Normalización y estandarización:** Se calcularon versiones escaladas por grupo usando **Min-Max** (`[0, 1]`) y **Z-Score** estándar.
* **Discretización y jerarquías:** Se discretizó la severidad a nivel CVE (`Bajo`, `Medio`, `Alto`, `Critico`) y la exposición mensual (`Sin_Exposicion`, `Bajo`, `Medio`, `Alto`, `Critico`), agregando jerarquía temporal (`anio → trimestre → periodo`) y tecnológica (`grupo → macro_categoria`).
* **Reducción:** Además del dataset completo de 24 variables (`data/gold/series_mensuales.csv`), se generó `data/gold/series_modelo.csv` con 13 variables seleccionadas sin redundancia para modelado.

---

## 3. Verificación y Lecciones Aprendidas
* **Pruebas automatizadas:** La suite completa (`tests/test_extractores.py` y `tests/test_silver_gold.py`) ejecutó **11 pruebas unitarias**, todas exitosas.
* **Lección técnica clave:** En `pandas 3.0`, las columnas vacías sin tipo explícito se crean como `object`, lo cual generó un `TypeError` al restar fechas cuando la tabla KEV de prueba estaba vacía; se corrigió tipando explícitamente `datetime64[ns]` en los DataFrames vacíos.
* **Automatización:** El pipeline completo (`Bronze → Silver → Gold`) quedó integrado en `.github/workflows/extraer.yml` para ejecutarse automáticamente cada semana junto con las pruebas unitarias.
