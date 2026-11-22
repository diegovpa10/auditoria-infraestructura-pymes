# Declaración de Ética, Legalidad y Gobernanza de Datos · Etapa E2

**Proyecto:** Observatorio de Exposición Digital de PYMES de Distribución (Colima)  
**Autor:** Diego Vargas  
**Institución:** TecNM / Instituto Tecnológico de Colima  
**Fecha de Emisión:** Noviembre 2026  
**Versión:** 2.0 (Etapa E2)  

---

## 1. Principios Rectores y Filosofía del Observatorio

El presente Observatorio tiene como objetivo cuantificar la exposición a riesgos cibernéticos y la distribución territorial de pequeñas y medianas empresas (pymes) dedicadas a la comercialización mayorista de insumos químicos y agroquímicos en el estado de Colima. El desarrollo del proyecto se fundamenta en cuatro pilares deontológicos universales:

1. **Beneficencia y Utilidad Social:** Proveer inteligencia de ciberseguridad accionable para un sector productivo crítico que históricamente carece de departamentos internos de Tecnologías de la Información (TI), reduciendo la asimetría informativa frente a amenazas digitales.
2. **No Maleficencia y No Intrusión:** Garantizar que ninguna fase del pipeline analítico interactúe de forma agresiva o intrusiva con las redes, activos informáticos o equipos de la empresa observada ni de las empresas registradas en el censo económico. No se realizan escaneos de puertos, peticiones directas a hosts de la pyme ni recolección de tráfico.
3. **Privacidad Estricta y Minimización de Datos ("Cero Datos Personales"):** Recolectar única y exclusivamente la información estrictamente necesaria para el modelado temporal y la agregación estadística, anonimizando o disociando cualquier identificador que pudiera comprometer a personas físicas o jurídicas.
4. **Transparencia y Trazabilidad Algorítmica:** Cada dato, pronóstico o métrica derivada debe ser matemáticamente auditable y criptográficamente rastreable hasta su fuente institucional primaria.

---

## 2. Términos de Uso y Marco Legal de Fuentes Oficiales

El observatorio consume datos de tres entidades públicas gubernamentales de máxima autoridad técnica y estadística. A continuación se analiza la conformidad jurídica de su uso:

```
+---------------------------------------------------------------------------------------------------+
| FUENTES OFICIALES CONSUMIDAS EN EL OBSERVATORIO                                                   |
+--------------------------+----------------------------+-------------------------------------------+
| Fuente Institucional     | Naturaleza Jurídica        | Tipo de Acceso / Licencia                 |
+--------------------------+----------------------------+-------------------------------------------+
| NIST NVD (API 2.0)       | Gobierno Federal EE. UU.   | Servicio Público REST / Dominio Público   |
| CISA KEV Feed            | Departamento de Seguridad  | CC0 1.0 Universal / Public Domain (17 USC)|
| INEGI DENUE (Colima 06)  | Instituto Nacional México  | Datos Abiertos / Libre Uso de Información |
+--------------------------+----------------------------+-------------------------------------------+
```

### 2.1 NIST National Vulnerability Database (NVD API 2.0)
* **Entidad Emisora:** National Institute of Standards and Technology (NIST), Department of Commerce, EE. UU.
* **Términos de Servicio:** La API 2.0 de NVD es provista como un bien público internacional sin costo ni restricciones sobre el procesamiento, modelado o redistribución de los registros CVE.
* **Cláusula de Atribución Obligatoria:** En estricto cumplimiento con la directriz del NIST, se declara explícitamente:
  > *"This product uses the NVD API but is not endorsed or certified by the NVD."*
* **Políticas Operativas (Fair Use):**
  - NIST impone una ventana temporal máxima de 120 días por petición (`pubStartDate` a `pubEndDate`). El extractor `src/bronze/nvd.py` fragmenta el horizonte histórico en ventanas seguras contiguas de 119 días (`DIAS_VENTANA = 119`).
  - Límites de tasa (*Rate Limiting*): 5 peticiones por ventana de 30 segundos sin API key (con pausa adaptativa implementada de 6.5 s) y 50 peticiones por ventana de 30 segundos con API key (`NVD_API_KEY`, con pausa de 0.7 s). Se incorpora manejo exponencial de reintentos ante respuestas HTTP 429.

### 2.2 CISA Known Exploited Vulnerabilities (KEV Catalog)
* **Entidad Emisora:** Cybersecurity and Infrastructure Security Agency (CISA), Department of Homeland Security, EE. UU.
* **Términos y Licencia:** Obra del Gobierno Federal de los Estados Unidos en el **Dominio Público** conforme a la Sección 105 del Título 17 del Código de los Estados Unidos (17 U.S.C. § 105) y licencia internacional **Creative Commons Zero (CC0 1.0 Universal)**.
* **Condiciones:** El catálogo se consume mediante su feed JSON oficial HTTPS. No se utilizan logotipos protegidos ni sellos oficiales de CISA en representaciones comerciales, empleándose exclusivamente para análisis académico y estadístico de amenazas activas.

### 2.3 INEGI DENUE (Directorio Estadístico Nacional de Unidades Económicas)
* **Entidad Emisora:** Instituto Nacional de Estadística y Geografía (INEGI), México.
* **Marco Normativo:** Ley del Sistema Nacional de Información Estadística y Geográfica (LSNIEG).
* **Términos de Libre Uso:** La información del DENUE forma parte de la **Política de Datos Abiertos del Gobierno Federal de México** y los **Términos de Libre Uso de la Información del INEGI**. Dichos términos facultan a cualquier usuario a:
  - Copiar, difundir, transformar, redistribuir y compilar la información de manera gratuita.
  - Generar productos derivados y herramientas computacionales.
* **Obligación de Atribución:** Citar al INEGI como fuente oficial: *"Fuente: INEGI, Directorio Estadístico Nacional de Unidades Económicas (DENUE), edición 2026, Estado de Colima."*
* **Mecanismos de Acceso Utilizados:** Se implementó soporte dual en `src/bronze/denue.py`:
  1. Descarga masiva directa autorizada del archivo abierto estatal `https://www.inegi.org.mx/contenidos/masiva/denue/denue_06_csv.zip`.
  2. Consulta autenticada vía token institucional a través de la API REST de desarrolladores del INEGI (`BuscarEntidad`).

---

## 3. Análisis Empírico de `robots.txt`

Para garantizar el cumplimiento de los estándares de accesibilidad y las directivas de indexación técnica, se inspeccionaron directamente los archivos `robots.txt` en la raíz de cada dominio institucional:

### 3.1 Portal `nvd.nist.gov`
* **Directivas Identificadas:** El portal web institucional está estructurado sobre una Single-Page Application (SPA) en Angular. Las directivas de `robots.txt` desaconsejan el rastreo no indexado (*web scraping*) de vistas dinámicas HTML.
* **Conformidad del Observatorio:** El observatorio **no realiza web scraping**. Toda la extracción se ejecuta exclusivamente contra el subdominio dedicado de la API REST oficial (`services.nvd.nist.gov/rest/json/cves/2.0`), el cual cuenta con endpoints REST documentados y abiertos específicamente diseñados para consumo automatizado por software.

### 3.2 Portal `cisa.gov`
* **Directivas Identificadas:**
  ```text
  User-agent: *
  Allow: /core/*.css$
  Allow: /core/*.js$
  Allow: /sites/default/files/*
  Disallow: /admin/
  Disallow: /user/
  ```
* **Conformidad del Observatorio:** El feed oficial del catálogo KEV está alojado en `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. Dicha ruta cae explícitamente en el segmento público permitido (`Allow: /sites/default/files/*`) y está expresamente diseñada para descarga directa por analistas de seguridad, automatizaciones SIEM y herramientas de investigación.

### 3.3 Portal `inegi.org.mx`
* **Directivas Identificadas (Verificación Empírica Real):**
  ```text
  User-Agent: *
  Allow: /app
  Allow: /temas
  Allow: /datos
  Allow: /datosprimarios
  Allow: /contenidos/productos
  Allow: /contenidos/programas
  Allow: /contenidos/temas
  Disallow: /auth/register/
  Disallow: /catalog/*/data-dictionary/*?file_name=*
  ```
* **Conformidad del Observatorio:**
  - El endpoint de la API REST de DENUE (`https://www.inegi.org.mx/app/api/denue/...`) está amparado bajo la regla explícita `Allow: /app`.
  - El paquete de descarga masiva abierta (`https://www.inegi.org.mx/contenidos/masiva/denue/denue_06_csv.zip`) se encuentra en las áreas autorizadas de contenidos y productos estadísticos.
  - Ninguna petición del extractor vulnera las rutas deshabilitadas (`Disallow`).

---

## 4. Mapeo de Licencias y Compatibilidad Jurídica

| Componente del Observatorio | Licencia de Origen | Compatibilidad con Repositorio (MIT) | Justificación Legal |
|---|---|---|---|
| **Catálogo CISA KEV** | Dominio Público / CC0 1.0 Universal | 100 % Compatible | La renuncia mundial de derechos patrimoniales permite redistribución, modificación e inclusión libre en proyectos bajo licencia MIT. |
| **API NIST NVD 2.0** | Obra de Gobierno Federal EE. UU. | 100 % Compatible | Datos abiertos de libre uso sin derechos de autor restrictivos, sujeto únicamente a la mención obligatoria de descargo (*disclaimer*). |
| **DENUE INEGI (Colima)** | Libre Uso de Información (México) | 100 % Compatible | La cláusula de libre uso faculta expresamente la creación de obras derivadas académicas y software con fines estadísticos citando la fuente. |
| **Código del Observatorio** | MIT License | Licencia Primaria | Permite a la comunidad académica y a las pymes auditar, clonar y adaptar libremente las herramientas desarrolladas. |

---

## 5. Mitigación Rigurosa de Sesgos Estadísticos y Metodológicos

En todo estudio de riesgo computacional y demografía económica existen sesgos intrínsecos que, de no ser controlados, conducen a conclusiones engañosas. El observatorio documenta y mitiga los siguientes sesgos:

```
SESGOS IDENTIFICADOS Y MECANISMOS DE MITIGACIÓN IMPLEMENTADOS
===================================================================================
1. Sesgo Tecnológico Global vs. Local:
   Problema: NVD sobre-reporta vulnerabilidades de fabricantes globales (Microsoft, HP).
   Mitigación: Mantenimiento del grupo CONTPAQi como hallazgo empírico (baja presencia de
               software local en taxonomías anglosajonas CVE) y análisis normalizado.

2. Sesgo de Selección por Palabras Clave (Proxies):
   Problema: 'dvr' o 'ip-camera' capturan tecnologías genéricas, no un modelo exacto.
   Mitigación: Documentación explícita de proxy tecnológico; agrupamiento conceptual
               en macro-categorías (Infraestructura_Red, Puesto_Trabajo, Operación).

3. Sesgo Temporal (Corte 2021-11):
   Problema: CVEs antiguos explotados en 2024 (ej. Office 2017) quedarían fuera de ventana.
   Mitigación: Tabla auxiliar 'kev_historico_catalogo.csv' y conteo histórico en Gold
               ('conteo_kev_catalogo') preservando la señal previa a 2021.

4. Sesgo de Valores Faltantes en CVSS (MAR):
   Problema: 3.83% de CVEs carecen de CVSS por encontrarse en revisión por NIST.
   Mitigación: Diagnóstico chi-cuadrado (p < 0.05 -> MAR) e imputación mediante mediana
               del grupo tecnológico con bandera de auditoría 'cvss_imputado = True'.

5. Sesgo Espacial y de Informalidad Económica (DENUE):
   Problema: DENUE captura preferentemente unidades económicas formales registradas.
   Mitigación: Estratificación por estrato de personal ocupado ('0 a 5', '6 a 10', '11 a 30')
               para evitar sobrerrepresentar a grandes cadenas frente a microdistribuidoras.
===================================================================================
```

---

## 6. Privacidad y Protección de Datos Personales ("Cero Datos Personales")

### 6.1 Cumplimiento Normativo (LFPDPPP y LGPDPPSO)
El tratamiento de datos del observatorio se rige estrictamente por la **Ley Federal de Protección de Datos Personales en Posesión de los Particulares (LFPDPPP)** y la **Ley General de Protección de Datos Personales en Posesión de Sujetos Obligados (LGPDPPSO)** mexicanas:
* **Principio de Proporcionalidad y Calidad:** Solo se utilizan datos disociados y agregados.
* **Principio de Responsabilidad:** Se adoptaron medidas técnicas automáticas para evitar la fuga accidental de nombres, ubicaciones privadas o información financiera.

### 6.2 Anonimización del Actor Participante (Entrevista E0)
La pyme distribuidora química con sede en Colima que participó en la entrevista diagnóstica se encuentra protegida bajo anonimato absoluto:
* No se publica la razón social, nombre del dueño, RFC, domicilio físico ni dirección IP.
* En toda la documentación y bases de datos se referencia únicamente como *"Pyme distribuidora de productos químicos en Colima"*.
* La información recabada en la entrevista se tradujo exclusivamente a un perfil abstracto de tecnologías presentes (Windows, CONTPAQi, módems, impresoras, cámaras IP).

### 6.3 Disociación y Anonimización de Establecimientos DENUE en Capa Silver
Aunque el DENUE es un directorio de acceso público, contiene campos que pueden corresponder al nombre de personas físicas con actividad empresarial (`nom_estab`, `raz_social`, teléfonos fijos o celulares, correos electrónicos particulares). Para blindar la privacidad:
* **Filtro de Descarte Inmediato:** El pipeline `src/silver/geo.py` elimina en memoria todas las columnas de contacto personal (`telefono`, `correoelec`, `www`, `nom_vial`, `numero_ext`, `edificio`, `nomb_asent`).
* **Seudonimización Determinista:** Los nombres comerciales y razones sociales se eliminan y se reemplazan por un identificador estadístico unívoco y neutral:
  $$\text{pyme\_id} = \text{PYME-DIST-COL-}001, \dots, \text{PYME-DIST-COL-}119$$
* **Conservación de Atributos Estadísticos:** Únicamente se mantienen la clave de actividad SCIAN (`codigo_act`), descripción genérica (`nombre_act`), municipio (`municipio`), estrato de personal (`estrato_personal`), coordenadas geográficas (`latitud`, `longitud`) y distancia euclidiana métrica (`distancia_centro_km`).

---

## 7. Matriz de Linaje Criptográfico y Trazabilidad Ética

Para asegurar que ningún registro sea alterado, inventado o descontextualizado a lo largo del flujo Bronze $\rightarrow$ Silver $\rightarrow$ Gold, cada artefacto cuenta con trazabilidad bidireccional y firma criptográfica SHA-256:

```
LINAJE Y TRAZABILIDAD CRIPTOGRÁFICA DE EXTREMO A EXTREMO
====================================================================================================
BRONZE:
  • NVD: data/bronze/nvd/{grupo}/{keyword}_{inicio}_{fin}.json.gz (.meta.json con sha256 y fecha)
  • KEV: data/bronze/kev/kev_YYYYMMDD.json.gz (.meta.json con sha256 y fecha)
  • DENUE: data/bronze/denue/denue_colima_quimicos.json.gz (.meta.json con sha256 y fecha)
            │
            ▼
SILVER (Puertas de Calidad Pandera + Cuarentena):
  • data/silver/vulnerabilidades.csv: 2,019 filas. Cada fila porta:
    - archivo_origen_nvd, sha256_origen_nvd, fecha_ingesta_nvd_utc
    - archivo_origen_kev, sha256_origen_kev, fecha_ingesta_kev_utc
    - id_linaje (Hash determinista de 16 caracteres)
  • data/silver/denue_colima_quimicos.csv: 119 filas anonimizadas. Cada fila porta:
    - archivo_origen_bronce, fecha_ingesta_bronce_utc, sha256_origen_bronce, id_linaje
            │
            ▼
GOLD (Agregaciones, Cruces de Riesgo y Series):
  • series_mensuales.csv (366 filas): archivos_origen_bronce, fecha_ingesta_bronce, sha256_origen_bronce, id_linaje
  • series_modelo.csv (366 filas reducidas): id_linaje, fecha_ingesta_bronce, archivos_origen_bronce
  • trazabilidad_cve_oro.csv (2,019 filas): mapeo granular 1 a 1 de cada CVE Gold hasta archivo crudo Bronze
  • denue_municipios_colima.csv (10 municipios): métricas de personal, centroides, sha256_origen_bronce, id_linaje
  • exposicion_geo_tecnologica.csv (10 municipios): cruce espacial y cibernético con trazabilidad completa
  • linaje_registros.csv: catálogo maestro con 100% de trazabilidad auditada de todas las tablas
====================================================================================================
```

Cualquier inconsistencia, corrupción de tipos o violación de rango geográfico es automáticamente interceptada por Pandera y desviada a las tablas de cuarentena (`data/cuarentena/cuarentena_silver.csv` y `data/cuarentena/cuarentena_denue.csv`), impidiendo que datos no conformes ingresen a la capa analítica final.
