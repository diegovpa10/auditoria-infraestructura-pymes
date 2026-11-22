# Relatoría de Etapa E2 · Fuente Especializada, Linaje Completo y Ética de Datos

**Proyecto:** Observatorio de exposición digital de pymes de distribución (Colima)  
**Etapa:** E2 (Unidad 4)  
**Fecha:** 2026-11-22  
**Autor:** Diego Vargas  

---

## 1. Propósito de la Etapa

La etapa E2 tuvo como propósito central enriquecer el Observatorio mediante la integración de una **fuente especializada avanzada** que proveyera contexto territorial al perfil de vulnerabilidades cibernéticas, implementar una **arquitectura de linaje y trazabilidad criptográfica total** que permita rastrear cada registro de la Capa Oro hasta su archivo crudo de ingesta en la Capa Bronce, y formalizar una **Declaración de Ética y Legalidad** con análisis empírico de términos de servicio, archivos `robots.txt`, licencias de datos, mitigación de sesgos estadísticos y salvaguardas rigurosas de privacidad (*Cero Datos Personales*).

---

## 2. Desafíos Encontrados y Decisiones de Diseño

### 2.1 Integración de la Fuente Especializada: DENUE (INEGI)
Para contextualizar territorialmente a la empresa observada en la entrevista E0 (*pyme distribuidora de productos químicos en Colima*), se integró el **Directorio Estadístico Nacional de Unidades Económicas (DENUE - INEGI)**.
* **Reto:** El acceso a la API REST de desarrolladores del INEGI requiere un token institucional personal que puede no estar configurado en entornos de integración continua (CI/CD) o ejecuciones desatendidas. Además, el endpoint REST segmenta consultas por radio de búsqueda en metros.
* **Decisión de Diseño:** Se diseñó en `src/bronze/denue.py` una estrategia de extracción de doble vía:
  1. Si se detecta la variable de entorno `INEGI_DENUE_TOKEN`, el extractor puede consumir directamente la API REST oficial de INEGI.
  2. Como vía primaria y resiliente, el extractor automatiza la descarga y descompresión directa del paquete oficial de datos abiertos para el estado de Colima (`denue_06_csv.zip`, alojado en los servidores de INEGI), filtrando en memoria el conjunto de datos para aislar exclusivamente las unidades económicas del sector mayorista de distribución química, fertilizantes y plaguicidas (SCIAN 464111 / 434111).
  3. El resultado crudo se preserva comprimido en `data/bronze/denue/denue_colima_quimicos.json.gz` acompañado de su firma `sha256_contenido` y fecha UTC en el archivo de metadatos `.meta.json`.

### 2.2 Procesamiento Espacial y Proyecciones Métricas con GeoPandas
Al incorporar coordenadas geográficas surgieron retos geométricos y de distancias:
* **Reto:** Las coordenadas geográficas estándar de DENUE se encuentran en grados decimales (latitud/longitud bajo el datum geodésico WGS 84 / `EPSG:4326`). Calcular distancias euclidianas en grados induce errores severos debido a la convergencia de meridianos.
* **Decisión de Diseño:** Se utilizó **GeoPandas** (`geopandas.GeoDataFrame`) y **Shapely** en `src/silver/geo.py`:
  - Se instanció la geometría espacial mediante `gpd.points_from_xy(df['longitud'], df['latitud'], crs="EPSG:4326")`.
  - Se re-proyectó la capa a **UTM Zona 13N (`EPSG:32613`)**, el sistema de coordenadas planas proyectadas en metros óptimo para el occidente de México y el estado de Colima.
  - Se calculó la distancia métrica real de cada establecimiento al centro neurálgico comercial de la capital de Colima (`distancia_centro_km`), permitiendo análisis de dispersión y accesibilidad logística.

### 2.3 Arquitectura de Linaje Criptográfico de Extremo a Extremo
Uno de los requisitos indispensables de E2 es garantizar que **ningún registro en la Capa Oro sea un dato flotante o carente de procedencia**.
* **Reto:** En la etapa E1, la capa Silver deduplicaba registros e imputaba faltantes, pero no preservaba explícitamente el nombre del archivo Bronze ni el hash criptográfico del paquete crudo de donde provino cada CVE individual.
* **Decisión de Diseño:** Se reestructuraron los pipelines `src/silver/limpieza.py` y `src/gold/series.py`:
  1. **En Capa Silver:** Al aplanar los JSON crudos de NVD y KEV, se inyectan las columnas de procedencia `archivo_origen_nvd`, `sha256_origen_nvd`, `fecha_ingesta_nvd_utc`, `archivo_origen_kev`, `sha256_origen_kev`, `fecha_ingesta_kev_utc` y un identificador determinista único:
     $$\text{id\_linaje} = \text{SHA-256}(\text{cve\_id} \parallel \text{grupo} \parallel \text{archivo\_origen})[:16]$$
  2. **En Capa Oro:** Al agrupar mensualmente por `(grupo, periodo)`, se agregan los nombres de archivos Bronze contribuyentes (`archivos_origen_bronce`), la fecha mínima de ingesta (`fecha_ingesta_bronce`) y el hash combinado (`sha256_origen_bronce`). Para los periodos sin vulnerabilidades (malla temporal contigua), se documenta explícitamente la procedencia institucional del calendario base (`config/grupos.json;bronze/catalogo_base`).
  3. **Tabla Granular de Trazabilidad (`data/gold/trazabilidad_cve_oro.csv`):** Se generó una tabla con los 2,019 registros únicos de vulnerabilidades que mapea uno a uno cada registro de la Capa Oro con el archivo `.json.gz` crudo y su timestamp exacto de ingesta.
  4. **Catálogo Maestro de Linaje (`data/gold/linaje_registros.csv`):** Auditoría consolidada de las 5 tablas Gold, documentando total de filas, fuentes Bronze, ventana temporal de ingesta y hashes SHA-256 verificables.

### 2.4 Privacidad y Principio de "Cero Datos Personales"
El directorio DENUE original contiene nombres de establecimientos (`nom_estab`) y razones sociales (`raz_social`) que con frecuencia coinciden con nombres de personas físicas, así como teléfonos y correos electrónicos.
* **Decisión de Diseño:** En `src/silver/geo.py`, se implementó una rutina estricta de **minimización y disociación de datos**:
  - Se eliminan de manera irreversible teléfonos, correos y páginas web privadas.
  - Se eliminan los nombres comerciales y razones sociales individuales, asignando un seudónimo neutral y determinista: `PYME-DIST-COL-001` a `119`.
  - Se conservan únicamente los atributos económicos agregados (código de actividad SCIAN, descripción de la clase de actividad, estrato de personal ocupado, municipio y coordenadas geográficas).
  - De esta forma, el observatorio cumple cabalmente con la Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP) y garantiza un entorno con **cero datos personales**.

### 2.5 Puertas de Calidad Pandera para Datos Geoespaciales
Para evitar que registros con coordenadas corruptas o fuera de Colima contaminen la Capa Oro:
* Se implementaron en `src/silver/calidad.py` los esquemas `esquema_denue_silver()` y `esquema_denue_gold()`.
* Se validan límites geográficos estrictos del estado de Colima: latitud en $[18.5, 19.6]$, longitud en $[-104.5, -103.4]$, municipios válidos dentro del catálogo oficial de 10 municipios y estratos de personal estandarizados.
* Los registros no conformes se desvían de inmediato con su motivo documentado a `data/cuarentena/cuarentena_denue.csv`. En los datos reales de DENUE Colima, los 119 registros resultaron válidos (0 en cuarentena); el bloqueo y desvío de cuarentena fue verificado con casos corruptos sintéticos en `tests/test_geo.py`.

### 2.6 Cruce Espacio-Temporal de Riesgo y Visualizaciones Cartográficas
En `src/gold/geo.py`:
* Se computó la concentración municipal de distribuidores mayoristas de insumos químicos (destacando Tecomán con 40 pymes y Colima con 27 pymes, concentrando conjuntamente el 56.3 % de la capacidad de distribución agroquímica del estado).
* Se construyó un **índice de exposición geo-tecnológica** combinando la severidad CVSS promedio del parque tecnológico de las pymes con la densidad municipal de empresas sin TI propio.
* Se generó un mapa cartográfico formal a 300 DPI con GeoPandas y Matplotlib en `docs/E2/mapa_exposicion_colima.png` (con rosa de los vientos, leyenda, cuadrícula geográfica y burbujas de concentración municipal), así como un mapa interactivo web en `docs/E2/mapa_distribucion.html` para inspección dinámica.

---

## 3. Verificación, Automatización CI/CD y Lecciones Aprendidas

* **Pruebas Automatizadas:** La suite de pruebas unitarias se expandió de 11 a **16 pruebas unitarias completas** distribuidas en `tests/test_extractores.py`, `tests/test_silver_gold.py` y `tests/test_geo.py`. Todas las pruebas ejecutan en modo simulado sin tocar la red, completando en 3.28 segundos con 100 % de éxito.
* **Automatización en GitHub Actions:** Se actualizó [.github/workflows/extraer.yml](../.github/workflows/extraer.yml) para ejecutar en cada corrida la extracción de DENUE, la limpieza espacial Silver con Pandera, la agregación Gold y la generación cartográfica, versionando los resultados y metadatos con control de cambios automático.
* **Lección Técnica Clave:** Al nombrar los módulos de la capa Silver y Gold como `geo.py`, se generó inicialmente una colisión de nombres en la suite de pruebas debido a la precedencia en `sys.path`. Se resolvió organizando las importaciones de forma modular (`from silver import geo as silver_geo; from gold import geo as gold_geo`) y asegurando la presencia de archivos `__init__.py` en cada paquete.
* **Registro de Calidad PSP:** Se registraron puntualmente las actividades, tiempos dedicados y defectos corregidos en `calidad/tiempo-diego.csv` y `calidad/defectos-diego.csv`.
