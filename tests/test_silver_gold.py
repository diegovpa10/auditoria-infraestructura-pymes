"""Pruebas unitarias para Capa Silver, Puerta de Calidad Pandera (cuarentena) y Capa Gold."""
import sys
import tempfile
import unittest
from pathlib import Path

import pandas as pd

RAIZ_PROYECTO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "bronze"))
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "silver"))
sys.path.insert(0, str(RAIZ_PROYECTO / "src" / "gold"))

import limpieza  # noqa: E402
import series  # noqa: E402


def _fila_nvd(**overrides) -> dict:
    base = {
        "cve_id": "CVE-2024-10001",
        "grupo": "windows_office",
        "keyword_origen": "windows-11",
        "vuln_status": "Analyzed",
        "published_raw": "2024-03-10T10:00:00.000",
        "last_modified_raw": "2024-03-12T12:00:00.000",
        "cvss_base_raw": 7.8,
        "cvss_version": "3.1",
        "attack_vector": "NETWORK",
        "cwe_principal": "CWE-79",
        "num_refs": 2,
        "descripcion": "Valid vulnerability description for testing.",
    }
    base.update(overrides)
    return base


class TestSilverYCuarentena(unittest.TestCase):
    def test_deduplicacion_imputacion_e_integracion_kev(self):
        nvd_df = pd.DataFrame(
            [
                _fila_nvd(cve_id="CVE-2024-10001", keyword_origen="windows-11", cvss_base_raw=8.0),
                # Duplicado por otra palabra clave en el mismo grupo (fecha posterior)
                _fila_nvd(
                    cve_id="CVE-2024-10001",
                    keyword_origen="microsoft-office",
                    last_modified_raw="2024-03-15T12:00:00.000",
                    cvss_base_raw=8.2,
                ),
                # Registro con CVSS faltante en estado Deferred -> debe imputarse con mediana del grupo
                _fila_nvd(
                    cve_id="CVE-2024-10002",
                    vuln_status="Deferred",
                    cvss_base_raw=None,
                    cvss_version=None,
                    attack_vector=None,
                    cwe_principal=None,
                ),
            ]
        )
        kev_df = pd.DataFrame(
            [
                {
                    "cve_id": "CVE-2024-10001",
                    "kev_date_added_raw": "2024-03-20",
                    "kev_due_date_raw": "2024-04-10",
                    "ransomware": "Known",
                    "vendor_project": "Microsoft",
                    "product": "Windows 11",
                    "kev_cwes": "CWE-79",
                    "grupo_keyword_kev": "windows_office",
                }
            ]
        )

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            res = limpieza.ejecutar_pipeline_silver(
                carpeta_bronze=t / "bronze",
                carpeta_silver=t / "silver",
                carpeta_cuarentena=t / "cuarentena",
                df_nvd_inyectado=nvd_df,
                df_kev_inyectado=kev_df,
            )
            self.assertEqual(res["duplicados_keyword_eliminados"], 1)
            self.assertEqual(res["registros_silver_validos"], 2)
            self.assertEqual(res["registros_cuarentena"], 0)
            self.assertEqual(res["coincidencias_nvd_kev"], 1)

            silver = pd.read_csv(t / "silver" / "vulnerabilidades.csv")
            fila1 = silver[silver["cve_id"] == "CVE-2024-10001"].iloc[0]
            self.assertEqual(fila1["cvss_base"], 8.2)
            self.assertTrue(bool(fila1["en_kev"]))
            self.assertEqual(fila1["ransomware"], "Known")
            self.assertEqual(fila1["dias_a_kev"], 10.0)

            fila2 = silver[silver["cve_id"] == "CVE-2024-10002"].iloc[0]
            self.assertTrue(bool(fila2["cvss_imputado"]))
            self.assertEqual(fila2["cvss_base"], 8.2)
            self.assertEqual(fila2["attack_vector"], "DESCONOCIDO")
            self.assertEqual(fila2["cwe_principal"], "SIN_CWE")

    def test_puerta_calidad_envia_invalidos_a_cuarentena(self):
        nvd_df = pd.DataFrame(
            [
                _fila_nvd(cve_id="CVE-2024-20001", cvss_base_raw=7.5),
                # 1. ID inválido
                _fila_nvd(cve_id="BAD-ID-99"),
                # 2. CVSS fuera de rango [0, 10]
                _fila_nvd(cve_id="CVE-2024-20002", cvss_base_raw=14.0),
                # 3. Estado rechazado
                _fila_nvd(cve_id="CVE-2024-20003", vuln_status="Rejected"),
                # 4. Fechas invertidas (last_modified < published)
                _fila_nvd(
                    cve_id="CVE-2024-20004",
                    published_raw="2024-05-10T00:00:00.000",
                    last_modified_raw="2024-05-01T00:00:00.000",
                ),
                # 5. Fecha corrupta
                _fila_nvd(cve_id="CVE-2024-20005", published_raw="fecha-no-valida"),
            ]
        )
        kev_df = pd.DataFrame(
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

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            res = limpieza.ejecutar_pipeline_silver(
                carpeta_bronze=t / "bronze",
                carpeta_silver=t / "silver",
                carpeta_cuarentena=t / "cuarentena",
                df_nvd_inyectado=nvd_df,
                df_kev_inyectado=kev_df,
            )
            self.assertEqual(res["registros_silver_validos"], 1)
            self.assertEqual(res["registros_cuarentena"], 5)

            silver = pd.read_csv(t / "silver" / "vulnerabilidades.csv")
            self.assertListEqual(silver["cve_id"].tolist(), ["CVE-2024-20001"])

            cuarentena = pd.read_csv(t / "cuarentena" / "cuarentena_silver.csv")
            self.assertEqual(len(cuarentena), 5)
            self.assertTrue(cuarentena["motivo_cuarentena"].notna().all())
            self.assertIn("BAD-ID-99", cuarentena["cve_id"].tolist())


class TestGoldSeries(unittest.TestCase):
    def test_agregacion_atipicos_normalizacion_y_reduccion(self):
        # Construir serie con variación normal y 1 pico extremo (40 CVEs)
        conteos = {"2024-01": 1, "2024-02": 2, "2024-03": 3, "2024-04": 40, "2024-05": 2, "2024-06": 3}
        filas = []
        for idx, (mes, n) in enumerate(conteos.items()):
            for j in range(n):
                filas.append(
                    {
                        "cve_id": f"CVE-2024-{idx}{j:03d}",
                        "grupo": "camaras_ip",
                        "macro_categoria": "Infraestructura_Red",
                        "periodo": mes,
                        "cvss_base": 9.2 if j == 0 else 6.0,
                        "severidad_discreta": "Critico" if j == 0 else "Medio",
                        "en_kev": False,
                        "ransomware": "No_KEV",
                    }
                )
        df_silver = pd.DataFrame(filas)
        gold = series.construir_series_gold(
            df_silver,
            grupos_validos=["camaras_ip", "contpaqi"],
            desde_periodo="2024-01",
            hasta_periodo="2024-06",
        )

        # 2 grupos * 6 meses = 12 filas; contpaqi rellenado con ceros
        self.assertEqual(len(gold), 12)
        cam = gold[gold["grupo"] == "camaras_ip"]
        pico = cam[cam["periodo"] == "2024-04"].iloc[0]
        self.assertTrue(bool(pico["es_atipico_iqr"]))
        self.assertTrue(bool(pico["es_atipico_mad"]))
        self.assertLess(pico["total_cves_tratado"], pico["total_cves"])

        # Verificar rangos Min-Max [0, 1]
        self.assertGreaterEqual(gold["total_cves_minmax"].min(), 0.0)
        self.assertLessEqual(gold["total_cves_minmax"].max(), 1.0)

        # Verificar ceros explícitos en contpaqi
        cont = gold[gold["grupo"] == "contpaqi"]
        self.assertTrue((cont["nivel_riesgo_mensual"] == "Sin_Exposicion").all())


if __name__ == "__main__":
    unittest.main()
