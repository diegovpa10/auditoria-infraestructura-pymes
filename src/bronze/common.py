"""Utilidades comunes de la capa Bronze: guardado crudo con metadatos de linaje."""
import gzip
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def cargar_grupos(ruta: Path | None = None) -> dict:
    ruta = ruta or RAIZ / "config" / "grupos.json"
    return json.loads(ruta.read_text(encoding="utf-8"))


def guardar_raw(ruta: Path, contenido: bytes, meta: dict) -> dict:
    """Guarda `contenido` comprimido (mtime fijo para diffs limpios) y un .meta.json
    con sha256, tamano y fecha de ingesta. Devuelve los metadatos."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "wb") as crudo:
        with gzip.GzipFile(fileobj=crudo, mode="wb", mtime=0) as gz:
            gz.write(contenido)
    meta = {
        **meta,
        "sha256_contenido": hashlib.sha256(contenido).hexdigest(),
        "bytes_contenido": len(contenido),
        "ingestado_utc": utcnow().isoformat(),
    }
    ruta_meta = ruta.parent / (ruta.name + ".meta.json")
    ruta_meta.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return meta


def leer_raw(ruta: Path):
    with gzip.open(ruta, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def coincide(texto: str, keywords: list[str]) -> bool:
    t = texto.lower()
    return any(k.lower() in t for k in keywords)
