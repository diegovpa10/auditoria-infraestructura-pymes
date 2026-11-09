"""Pruebas con respuestas SIMULADAS (no tocan la red). Ejecuta: python -m unittest discover -s tests"""
import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "bronze"))

import check_periodos  # noqa: E402
import common  # noqa: E402
import kev  # noqa: E402
import nvd  # noqa: E402


class Resp:
    def __init__(self, datos, status=200):
        self._d, self.status_code = datos, status

    def json(self):
        return self._d


class SesionFalsa:
    def __init__(self, respuestas):
        self.respuestas, self.llamadas = list(respuestas), []

    def get(self, url, params=None, headers=None, timeout=None):
        self.llamadas.append((url, params, headers))
        return self.respuestas.pop(0)


def cve(id_, pub):
    return {"cve": {"id": id_, "published": pub}}


class TestVentanas(unittest.TestCase):
    def test_ninguna_ventana_supera_120_dias_y_cubre_todo(self):
        v = list(nvd.ventanas(date(2021, 11, 1), date(2026, 11, 8)))
        for a, b in v:
            self.assertLessEqual((b - a).days + 1, 120)
        self.assertEqual(v[0][0], date(2021, 11, 1))
        self.assertEqual(v[-1][1], date(2026, 11, 8))
        for (_, b1), (a2, _) in zip(v, v[1:]):
            self.assertEqual((a2 - b1).days, 1)


class TestNVD(unittest.TestCase):
    def test_paginacion_y_guardado_con_metadatos(self):
        p1 = {"resultsPerPage": 1, "totalResults": 2, "vulnerabilities": [cve("CVE-1", "2024-01-05T00:00:00")]}
        p2 = {"resultsPerPage": 1, "totalResults": 2, "vulnerabilities": [cve("CVE-2", "2024-01-06T00:00:00")]}
        s = SesionFalsa([Resp(p1), Resp(p2)])
        orig = nvd.time.sleep
        nvd.time.sleep = lambda _: None
        try:
            datos = nvd.descargar_ventana(s, "zte", date(2024, 1, 1), date(2024, 4, 28))
        finally:
            nvd.time.sleep = orig
        paginas = json.loads(datos)
        self.assertEqual(len(paginas), 2)
        self.assertEqual(s.llamadas[1][1]["startIndex"], 1)

    def test_reintenta_ante_429(self):
        ok = {"resultsPerPage": 2000, "totalResults": 0, "vulnerabilities": []}
        s = SesionFalsa([Resp({}, 429), Resp(ok)])
        orig = nvd.time.sleep
        nvd.time.sleep = lambda _: None
        try:
            self.assertEqual(nvd.pedir_pagina(s, {}, None), ok)
        finally:
            nvd.time.sleep = orig

    def test_error_no_recuperable_lanza(self):
        with self.assertRaises(RuntimeError):
            nvd.pedir_pagina(SesionFalsa([Resp({}, 404)]), {}, None)

    def test_idempotencia_ventana_cerrada_no_se_repite(self):
        ok = {"resultsPerPage": 2000, "totalResults": 0, "vulnerabilities": []}
        with tempfile.TemporaryDirectory() as d:
            n = len(list(nvd.ventanas(date(2024, 1, 1), date(2024, 4, 28))))
            kws = sum(len(g["keywords"]) for g in common.cargar_grupos()["grupos"].values())
            orig = nvd.time.sleep
            nvd.time.sleep = lambda _: None
            try:
                args = ["--salida", d, "--desde", "2024-01-01", "--hasta", "2024-04-28"]
                s1 = SesionFalsa([Resp(ok)] * (n * kws))
                nvd.main(args, session=s1, hoy=date(2026, 11, 8))
                self.assertEqual(len(s1.llamadas), n * kws)
                s2 = SesionFalsa([])
                nvd.main(args, session=s2, hoy=date(2026, 11, 8))
                self.assertEqual(len(s2.llamadas), 0)
            finally:
                nvd.time.sleep = orig
            metas = list(Path(d).rglob("*.meta.json"))
            self.assertTrue(metas)
            self.assertIn("sha256_contenido", json.loads(metas[0].read_text()))


class TestKEV(unittest.TestCase):
    def test_guarda_snapshot_y_rechaza_feed_vacio(self):
        feed = {"vulnerabilities": [{"cveID": "CVE-1", "vendorProject": "Microsoft", "product": "Windows 11", "dateAdded": "2024-03-12"}]}
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(kev.main(["--salida", d], session=SesionFalsa([Resp(feed)])), 0)
            self.assertTrue(list(Path(d).glob("kev_*.json.gz")))
        with self.assertRaises(RuntimeError):
            kev.descargar(SesionFalsa([Resp({"vulnerabilities": []})]))

    def test_conteo_mensual_por_grupo(self):
        feed = {"vulnerabilities": [
            {"vendorProject": "Microsoft", "product": "Windows 11", "dateAdded": "2024-03-12"},
            {"vendorProject": "Microsoft", "product": "Windows 11", "dateAdded": "2024-03-20"},
            {"vendorProject": "Otro", "product": "X", "dateAdded": "2024-03-21"},
        ]}
        with tempfile.TemporaryDirectory() as d:
            kev.main(["--salida", d], session=SesionFalsa([Resp(feed)]))
            out = check_periodos.kev_por_mes(Path(d), common.cargar_grupos()["grupos"])
        self.assertEqual(out["windows_office"]["2024-03"], 2)
        self.assertEqual(sum(out["contpaqi"].values()), 0)


class TestPeriodos(unittest.TestCase):
    def test_meses_cubiertos(self):
        self.assertEqual(check_periodos.meses_cubiertos({"2021-11": 1, "2024-10": 3}), 36)
        self.assertEqual(check_periodos.meses_cubiertos({}), 0)


if __name__ == "__main__":
    unittest.main()
