# Observatorio de exposición digital de pymes de distribución

Proyecto integrador (Ingeniería de Datos · Informática enfocada a calidad · Análisis Estadístico), TecNM Colima.

**Idea:** Una pyme de distribución de productos químicos en Colima (anonimizada) usa tecnologías comunes (módems, cámaras IP, Windows/Office, impresoras, software contable/facturación CONTPAQi y soporte remoto). El observatorio construye series de tiempo mensuales de vulnerabilidades públicas de esas tecnologías (NIST NVD y CISA KEV), contextualiza territorialmente a los distribuidores mayoristas de agroquímicos del estado mediante **DENUE (INEGI)** y genera un diagnóstico continuo de exposición al riesgo digital.

**Limitación (explícita):** Las series describen vulnerabilidades del *parque tecnológico* y la demografía empresarial del sector, no intrusiones consumadas en redes de empresas específicas. La falta de detección de incidentes en microempresas sin departamento de TI es en sí misma un hallazgo de exposición.

---

## Estructura del Repositorio

```
config/
  grupos.json                     Configuración de grupos de tecnología, ventanas y palabras clave
src/
  bronze/                         Extractores Bronze (nvd.py, kev.py, denue.py, check_periodos.py)
  silver/                         Limpieza, diagnóstico MAR, imputación, GeoPandas y Pandera (limpieza.py, geo.py, calidad.py)
  gold/                           Series agregadas, cruce geo-tecnológico y cartografía (series.py, geo.py)
data/
  bronze/                         Datos crudos comprimidos (.json.gz) con metadatos (.meta.json, SHA-256)
  silver/                         Vulnerabilidades limpias y DENUE Colima anonimizado (Cero Datos Personales)
  gold/                           Series mensuales, modelo reducido, resumen municipal, cruce y linaje maestro
  cuarentena/                     Registros corruptos o fuera de límites desviados por Pandera (silver y geo)
tests/                            16 pruebas unitarias simuladas (sin tocar red): extractores, linaje y mapas
calidad/                          Bitácoras PSP (tiempo-diego.csv, defectos-diego.csv)
docs/
  etica-datos.md                  Declaración de Ética, Legalidad, robots.txt, licencias y privacidad
  relatoria-E1.md                 Relatoría técnica de la etapa E1
  relatoria-E2.md                 Relatoría técnica de la etapa E2
  E0/                             Propuesta inicial y ficha de entrega E0
  E1/                             Ficha de entrega E1 y notebook de exploración estadística
  E2/                             Ficha de entrega E2, mapa PNG a 300 DPI y mapa interactivo HTML
.github/workflows/
  extraer.yml                     Workflow CI/CD de ejecución periódica (lunes) y manual
```

---

## Ejecución Rápida

### 1. Instalación de Dependencias
```bash
pip install -r requirements.txt
```

### 2. Pruebas Automatizadas
```bash
python -m unittest discover -s tests
```

### 3. Pipeline Completo de Datos (Bronze -> Silver -> Gold)
```bash
# Capa Bronze (Extracción cruda con metadatos)
python src/bronze/kev.py
python src/bronze/nvd.py          # Opcional: export NVD_API_KEY=... para mayor velocidad
python src/bronze/denue.py        # Opcional: export INEGI_DENUE_TOKEN=... (fallback a descarga masiva)
python src/bronze/check_periodos.py

# Capa Silver (Puertas de Calidad Pandera, MCAR/MAR, GeoPandas UTM 13N y Anonimización)
python src/silver/limpieza.py
python src/silver/geo.py

# Capa Gold (Series mensuales, reducidas, agregación municipal, mapas y linaje maestro)
python src/gold/series.py
python src/gold/geo.py
```

---

## Ética, Legalidad y Linaje Criptográfico (E2)

1. **Cero Datos Personales:** El observatorio cumple estrictamente con la legislación mexicana (LFPDPPP y LGPDPPSO). En la capa Silver se disocian irreversiblemente todos los nombres comerciales, razones sociales, teléfonos y correos, utilizando seudónimos neutrales (`PYME-DIST-COL-001` a `119`).
2. **Conformidad de robots.txt y Términos de Servicio:** Se auditaron empíricamente los archivos `robots.txt` de NIST, CISA e INEGI, garantizando que el 100 % del tráfico ocurre mediante endpoints REST y descargas masivas de datos abiertos expresamente permitidas.
3. **Trazabilidad 100 % Verificable:** Cada registro de la Capa Oro (`series_mensuales.csv`, `denue_municipios_colima.csv`, `exposicion_geo_tecnologica.csv`) cuenta con `id_linaje`, ruta del archivo Bronze de origen, timestamp UTC y hash SHA-256 de integridad verificable.
4. **Visualizaciones Cartográficas:** Generación de mapa formal a 300 DPI en `docs/E2/mapa_exposicion_colima.png` y mapa interactivo en `docs/E2/mapa_distribucion.html`.

Ver detalles completos en [docs/etica-datos.md](docs/etica-datos.md) y [docs/E2/ENTREGA.md](docs/E2/ENTREGA.md).
