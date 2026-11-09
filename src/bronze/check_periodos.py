"""Revisa cuantos periodos mensuales cubre cada grupo (meta: >= 36).

Cuenta KEV por mes de `dateAdded` y NVD por mes de `cve.published` (sin duplicar CVE).
Un grupo con pocos CVE tendra meses en cero: eso es parte del hallazgo, pero la serie
sigue teniendo tantos periodos como meses cubiertos.
"""
import sys
from collections import defaultdict
from pathlib import Path

from common import RAIZ, cargar_grupos, coincide, leer_raw


def kev_por_mes(carpeta: Path, grupos: dict) -> dict:
    archivos = sorted(carpeta.glob("kev_*.json.gz"))
    out = {g: defaultdict(int) for g in grupos}
    if not archivos:
        return out
    for v in leer_raw(archivos[-1])["vulnerabilities"]:
        texto = f"{v.get('vendorProject', '')} {v.get('product', '')}"
        for g, info in grupos.items():
            if coincide(texto, info["keywords"]):
                out[g][v["dateAdded"][:7]] += 1
    return out


def nvd_por_mes(carpeta: Path, grupos: dict) -> dict:
    out = {g: defaultdict(int) for g in grupos}
    vistos = {g: set() for g in grupos}
    for g in grupos:
        for f in (carpeta / g).glob("*.json.gz") if (carpeta / g).exists() else []:
            for pag in leer_raw(f):
                for item in pag["respuesta"].get("vulnerabilities", []):
                    cve = item["cve"]
                    if cve["id"] in vistos[g]:
                        continue
                    vistos[g].add(cve["id"])
                    out[g][cve["published"][:7]] += 1
    return out


def meses_cubiertos(serie: dict) -> int:
    if not serie:
        return 0
    a, b = min(serie), max(serie)
    return (int(b[:4]) - int(a[:4])) * 12 + int(b[5:7]) - int(a[5:7]) + 1


def main() -> int:
    cfg = cargar_grupos()
    grupos = cfg["grupos"]
    kev = kev_por_mes(RAIZ / "data" / "bronze" / "kev", grupos)
    nvd = nvd_por_mes(RAIZ / "data" / "bronze" / "nvd", grupos)
    print(f"{'grupo':<18}{'KEV meses c/dato':>18}{'NVD span meses':>16}{'NVD CVE':>9}")
    for g in grupos:
        print(f"{g:<18}{len(kev[g]):>18}{meses_cubiertos(nvd[g]):>16}{sum(nvd[g].values()):>9}")
    print("\nMeta: >= 36 periodos mensuales en la serie que uses (NVD cubre desde 2021-11 => ~60).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
