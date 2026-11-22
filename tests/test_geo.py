"""Pruebas unitarias para la fuente especializada geoespacial DENUE (Bronze, Silver y Gold).
Verifica extracción simulada, anonimización (Cero Datos Personales), cálculo métrico con GeoPandas,
puerta de calidad Pandera con cuarentena y trazabilidad completa de registros.
"""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import pandas as pd

RAIZ_PROYECTO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ_PROYECTO / "src"))
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "bronze"))

import denue  # noqa: E402
from silver import geo as silver_geo  # noqa: E402
from gold import geo as gold_geo  # noqa: E402


class RespSimulada:
    def __init__(self, datos, status_code=200, headers=None):
        self._datos = datos
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self.text = json.dumps(datos) if isinstance(datos, (list, dict)) else str(datos)
        if isinstance(datos, bytes):
            self.content = datos
        else:
            self.content = self.text.encode("utf-8")

    def json(self):
        return self._datos


class SesionSimulada:
    def __init__(self, respuestas: list[RespSimulada]):
        self.respuestas = list(respuestas)
        self.llamadas = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.llamadas.append((url, params, headers))
        return self.respuestas.pop(0)


def _registro_denue_crudo(**overrides) -> dict:
    base = {
        "id": 12345,
        "clee": "060024641110001",
        "nom_estab": "DISTRIBUIDORA QUIMICA DEL PACIFICO SA DE CV",
        "raz_social": "JUAN PEREZ LOPEZ",
        "codigo_act": 464111,
        "nombre_act": "Comercio al por mayor de fertilizantes, plaguicidas y semillas para siembra",
        "per_ocu": "0 a 5 personas",
        "municipio": "Colima",
        "cve_mun": 2,
        "latitud": 19.2433,
        "longitud": -103.7247,
        "telefono": "3123123456",
        "correoelec": "contacto@distquimica.com",
    }
    base.update(overrides)
    return base


class TestDenueBronze(unittest.TestCase):
    def test_filtrado_sector_quimico_y_descarga_simulada(self):
        filas = [
            _registro_denue_crudo(id=1, nombre_act="Comercio al por mayor de fertilizantes y plaguicidas"),
            _registro_denue_crudo(id=2, nombre_act="Comercio al por menor de ropa"),  # No coincide
            _registro_denue_crudo(id=3, nombre_act="Comercio al por mayor de productos químicos industriales"),
        ]
        filtrados = denue.filtrar_establecimientos_quimicos(filas)
        self.assertEqual(len(filtrados), 2)
        self.assertEqual(filtrados[0]["id"], 1)
        self.assertEqual(filtrados[1]["id"], 3)

    def test_extraccion_desde_zip_simulado(self):
        df_csv = pd.DataFrame([
            _registro_denue_crudo(id=10, nombre_act="Comercio al por mayor de fertilizantes"),
            _registro_denue_crudo(id=20, nombre_act="Venta de abarrotes"),
        ])
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("conjunto_de_datos/denue_inegi_06_.csv", df_csv.to_csv(index=False).encode("latin1"))

        extraidos = denue.extraer_denue_desde_zip(buf.getvalue())
        self.assertEqual(len(extraidos), 1)
        self.assertEqual(extraidos[0]["id"], 10)


class TestDenueSilver(unittest.TestCase):
    def test_anonimizacion_cero_datos_personales_y_geopandas(self):
        crudos = [
            _registro_denue_crudo(id=101, municipio="Colima", cve_mun=2, latitud=19.2433, longitud=-103.7247),
            _registro_denue_crudo(id=102, municipio="Tecomán", cve_mun=9, latitud=18.9130, longitud=-103.8760),
        ]
        meta = {
            "archivo": "denue/denue_colima_quimicos.json.gz",
            "sha256_contenido": "test_sha256_hash_abc",
            "ingestado_utc": "2026-11-22T20:00:00+00:00",
        }

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            res = silver_geo.ejecutar_pipeline_geo_silver(
                carpeta_bronze=t / "bronze",
                carpeta_silver=t / "silver",
                carpeta_cuarentena=t / "cuarentena",
                datos_inyectados=crudos,
                meta_inyectada=meta,
            )
            self.assertEqual(res["registros_silver_validos"], 2)
            self.assertEqual(res["registros_cuarentena"], 0)

            df_silver = pd.read_csv(t / "silver" / "denue_colima_quimicos.csv")
            # Cero datos personales: no debe existir nom_estab ni raz_social ni telefono
            self.assertNotIn("nom_estab", df_silver.columns)
            self.assertNotIn("raz_social", df_silver.columns)
            self.assertNotIn("telefono", df_silver.columns)
            self.assertNotIn("correoelec", df_silver.columns)

            # Identificadores disociados
            self.assertEqual(df_silver["pyme_id"].iloc[0], "PYME-DIST-COL-001")
            self.assertEqual(df_silver["pyme_id"].iloc[1], "PYME-DIST-COL-002")

            # Cálculo de distancia métrica euclidiana con GeoPandas
            self.assertIn("distancia_centro_km", df_silver.columns)
            # El punto de Colima capital está en el centro (~0 km)
            self.assertLess(df_silver[df_silver["municipio"] == "Colima"]["distancia_centro_km"].iloc[0], 2.0)
            # El punto de Tecomán dista ~35-45 km de la capital
            self.assertGreater(df_silver[df_silver["municipio"] == "Tecomán"]["distancia_centro_km"].iloc[0], 30.0)

            # Linaje verificable
            self.assertEqual(df_silver["archivo_origen_bronce"].iloc[0], "denue/denue_colima_quimicos.json.gz")
            self.assertEqual(df_silver["sha256_origen_bronce"].iloc[0], "test_sha256_hash_abc")
            self.assertTrue(df_silver["id_linaje"].iloc[0])

    def test_puerta_calidad_cuarentena_coordenadas_invalidas(self):
        crudos = [
            _registro_denue_crudo(id=1, latitud=19.2433, longitud=-103.7247),  # Válido Colima
            _registro_denue_crudo(id=2, latitud=45.0, longitud=-75.0),  # Fuera de Colima / México
            _registro_denue_crudo(id=3, municipio="Municipio_Inexistente"),  # Municipio inválido
        ]
        meta = {"archivo": "test.json.gz", "sha256_contenido": "hash_test", "ingestado_utc": "2026-11-22T00:00:00+00:00"}

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            res = silver_geo.ejecutar_pipeline_geo_silver(
                carpeta_bronze=t / "bronze",
                carpeta_silver=t / "silver",
                carpeta_cuarentena=t / "cuarentena",
                datos_inyectados=crudos,
                meta_inyectada=meta,
            )
            self.assertEqual(res["registros_silver_validos"], 1)
            self.assertEqual(res["registros_cuarentena"], 2)

            cuar = pd.read_csv(t / "cuarentena" / "cuarentena_denue.csv")
            self.assertEqual(len(cuar), 2)
            self.assertIn("motivo_cuarentena", cuar.columns)


class TestDenueGoldYCartografia(unittest.TestCase):
    def test_agregacion_municipal_y_linaje_maestro(self):
        df_silver = pd.DataFrame([
            {
                "pyme_id": "PYME-DIST-COL-001",
                "clee": "06002",
                "codigo_act": 464111,
                "nombre_act": "Quimicos",
                "estrato_personal": "0 a 5 personas",
                "municipio": "Colima",
                "cve_mun": 2,
                "latitud": 19.24,
                "longitud": -103.72,
                "distancia_centro_km": 0.5,
                "archivo_origen_bronce": "denue/denue_colima_quimicos.json.gz",
                "fecha_ingesta_bronce_utc": "2026-11-22T20:00:00+00:00",
                "sha256_origen_bronce": "hash_bronce_123",
                "id_linaje": "linaje_col_001",
            },
            {
                "pyme_id": "PYME-DIST-COL-002",
                "clee": "06009",
                "codigo_act": 464111,
                "nombre_act": "Fertilizantes",
                "estrato_personal": "6 a 10 personas",
                "municipio": "Tecomán",
                "cve_mun": 9,
                "latitud": 18.91,
                "longitud": -103.87,
                "distancia_centro_km": 40.0,
                "archivo_origen_bronce": "denue/denue_colima_quimicos.json.gz",
                "fecha_ingesta_bronce_utc": "2026-11-22T20:00:00+00:00",
                "sha256_origen_bronce": "hash_bronce_123",
                "id_linaje": "linaje_tec_002",
            },
        ])

        mun_gold = gold_geo.construir_resumen_municipal(df_silver)
        self.assertEqual(len(mun_gold), 10)  # Los 10 municipios de Colima
        self.assertEqual(mun_gold[mun_gold["municipio"] == "Colima"]["total_pymes"].iloc[0], 1)
        self.assertEqual(mun_gold[mun_gold["municipio"] == "Tecomán"]["total_pymes"].iloc[0], 1)
        self.assertEqual(mun_gold[mun_gold["municipio"] == "Manzanillo"]["total_pymes"].iloc[0], 0)

        # Generación de mapas
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            png_out = t / "mapa.png"
            html_out = t / "mapa.html"
            gold_geo.generar_visualizacion_cartografica(df_silver, mun_gold, png_out, html_out)
            self.assertTrue(png_out.exists())
            self.assertGreater(png_out.stat().st_size, 5000)
            self.assertTrue(html_out.exists())
            self.assertIn("leaflet", html_out.read_text(encoding="utf-8").lower())


if __name__ == "__main__":
    unittest.main()
