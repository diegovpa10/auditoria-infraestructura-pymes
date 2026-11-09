# Propuesta E0 · Observatorio de exposición digital de pymes de distribución

Equipo: _Diego Vargas_ · Fecha: Lunes 9 de noviembre del 2026

## 1. Ficha del actor
Pyme distribuidora de productos químicos en Colima (anonimizada). Sin TI interno; soporte externo. Tecnologías: módems de dos proveedores de internet, cámaras IP genéricas, 3 PCs de escritorio y 1 all-in-one con Windows 11 Pro, Office anual, impresoras HP, software de gestión y facturación (CONTPAQi), terminales de pago, soporte remoto de un proveedor externo.

## 2. Entrevista
--Entrevistado prefiere el anonimato, debido a que estara publico en GitHub, cargo: Dueño,

¿Qué sistemas o herramientas digitales usan para pedidos, inventario y facturación? CONTPAQi (Compact y NomiPack) y Paqueteria de Office oficial pago anual.

¿Qué se detendría si perdieran la computadora principal o el correo por un día? Las facturaciones y el registro de pedidos realizados y pendientes, tendrian que recurir a sus anotaciones en papel.

¿Han recibido facturas, pagos o pedidos que parecieran falsos, o mensajes sospechosos? Si, extorsiones o pedir datos extraños.

¿Cómo respaldan su información y quién se encarga de eso? No se respalda, se encuentra en el disco duro de cada computadora y ahi se guarda respectivamente lo de cada equipo.

Si les pasara algo, ¿cómo se darían cuenta? La lentitud de los equipos, caida de pedidos, problemas con el SAT, clientes quejandose, etc.

## 3. Preguntas analíticas
1. **E1 (series de tiempo):** ¿Cuántas vulnerabilidades nuevas (KEV y CVE críticos) se publicarán por mes en cada grupo de tecnología durante los próximos 6 meses?
2. **E2 (adaptar al temario):** ¿Qué factores (método de pronóstico, ventana histórica, nivel de agregación) cambian más la precisión del pronóstico?
3. **E3 (comparación):** ¿Difieren los grupos en severidad CVSS, días entre publicación y entrada a KEV, y uso en ransomware?

## 4. Plan de datos
| Fuente | Qué aporta | Frecuencia | Acceso |
|---|---|---|---|
| CISA KEV | CVE explotados activamente, `dateAdded` | semanal (snapshot) | JSON público |
| NVD API 2.0 | CVE por palabra clave, fecha de publicación, CVSS | semanal | API pública, key gratuita opcional |
| DENUE (INEGI), E2 | contexto geoespacial de distribuidores | única | por verificar (token) |

Series: mensuales desde 2021-11 (≈60 periodos; meta ≥ 36). Capas: Bronze (crudo + metadatos) → Silver (limpio, validado) → Gold (series por grupo).

## 5. Análisis ético y legal
- Fuentes públicas y no intrusivas: Solo se consumen APIs y feeds públicos; no se realiza escaneo de redes, sondeo de puertos ni acceso a sistemas de la empresa.
- Anonimización del actor: El negocio se mantiene anónimo bajo la denominación genérica «pyme distribuidora de productos químicos en Colima»; no se publican nombres comerciales, razones sociales, RFC, IPs ni credenciales.
- Términos de NIST NVD:
  - Servicio público de NIST (gobierno de EE. UU.) sin restricciones para análisis y redistribución de datos.
  - Atribución obligatoria incorporada: "This product uses the NVD API but is not endorsed or certified by the NVD."
  - Límites de la API 2.0: Ventana temporal máxima de 120 días por petición (DIAS_VENTANA = 119 en el código). Rate limit de 5 peticiones por ventana de 30 s sin API key (pausa de 6.5 s implementada) y 50 peticiones con key (pausa de 0.7 s).
- Términos de CISA KEV (Dominio Público):
  - El catálogo de vulnerabilidades explotadas (KEV) es una obra del Gobierno Federal de EE. UU. en el Dominio Público (17 U.S.C. § 105 / CC0). Libre descarga y redistribución. (Nota: no confundir con el programa bilateral AIS de CISA, el cual no aplica a este feed público).
  - Se utiliza tal cual (as-is) sin uso indebido de los logotipos oficiales de CISA.
- DENUE (INEGI - para E2):
  - Libre acceso y consulta bajo la política de datos abiertos del INEGI citando la fuente.
  - Requiere un token de consulta gratuito que se obtiene registrando un correo institucional.

## 6. Limitaciones conocidas
- Las palabras clave son proxies; «cámaras IP genéricas» y «soporte remoto» no se asocian a un producto concreto.
- Puede haber grupos con casi cero CVE (p. ej. CONTPAQi); se reporta como hallazgo, y para pronosticar se agrega por grupo.
- Datos por confirmar: marca del módem Megacable, modelo de cámaras, herramienta de soporte remoto del proveedor.

## 7. Metas de calidad (medibles)
1. 100 % de archivos Bronze con `.meta.json` (sha256, URL, parámetros, fecha) verificable.
2. Pruebas automatizadas pasando en el 100 % de las ejecuciones del workflow antes de extraer.
3. 0 secretos o datos identificables en el repositorio (búsqueda antes de cada tag).

## 8. Registro PSP
Tiempo y defectos por integrante en `calidad/`.
