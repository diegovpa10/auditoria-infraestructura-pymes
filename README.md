# Observatorio de exposición digital de pymes de distribución

Proyecto integrador (Ingeniería de Datos · Informática enfocada a calidad · Análisis Estadístico), TecNM Colima.

**Idea:** una pyme de distribución de productos químicos en Colima (anonimizada) usa un puñado de tecnologías comunes (módems, cámaras IP, Windows/Office, impresoras, software de facturación, soporte remoto). Construimos series de tiempo mensuales de vulnerabilidades públicas de esas tecnologías (CISA KEV y NVD) y un boletín mensual de riesgo para este tipo de negocio.

**Limitación (explícita):** las series describen vulnerabilidades de las *tecnologías*, no ataques al negocio. Que la empresa no reporte ataques conocidos es un hallazgo en sí (falta de detección).

## Estructura

```
config/grupos.json        grupos de tecnología y palabras clave
src/bronze/               extractores (kev.py, nvd.py) y revisión de periodos
data/bronze/              respuestas crudas comprimidas + .meta.json (linaje, sha256)
tests/                    pruebas con respuestas simuladas
calidad/                  registros PSP de tiempo y defectos
docs/E0/                  propuesta y guía de entrega
.github/workflows/        extracción programada (lunes) y manual
```

## Uso

```bash
pip install -r requirements.txt
python -m unittest discover -s tests
python src/bronze/kev.py
python src/bronze/nvd.py          # opcional: export NVD_API_KEY=... (gratis) para ir más rápido
python src/bronze/check_periodos.py
```

## Seguridad y ética

- Solo se consumen fuentes públicas. No se escanea ninguna red ni equipo.
- No se publican contraseñas, IPs, marcas/modelos que identifiquen al negocio ni datos internos. El negocio se refiere como "pyme distribuidora".
- Los términos de uso de NVD, CISA y (más adelante) INEGI/DENUE deben revisarse antes de publicar datasets. Ver `docs/E0/propuesta.md`.

## Estado de verificación

Los extractores tienen pruebas con respuestas simuladas, **pero aún no se han corrido contra las APIs reales**. La primera ejecución manual del workflow (Actions → extraer-bronze → Run workflow) es esa prueba.
