"""
agent/decoy_manager.py
Crea file "civetta" con nomi appetibili per un ransomware, calcola e salva
il loro hash di baseline. Qualsiasi modifica futura a questi file è un
segnale di altissima confidenza: nessun utente/processo legittimo dovrebbe
mai toccarli.
"""
import os
import hashlib
import json
import random

DECOY_NAMES = [
    "Fatture_2024.xlsx", "Password_Aziendali.docx", "Backup_Database.sql",
    "Contratti_Clienti.pdf", "Stipendi_Dipendenti.xlsx", "Dati_Bancari.docx",
    "Progetti_Riservati.zip", "Report_Finanziario_Q4.xlsx", "Credenziali_Server.txt",
    "Piano_Aziendale_2025.pptx", "Documenti_Legali.pdf", "Archivio_Clienti.csv",
]

FILLER_TEXT = (
    "Questo e' un file esca (canary/decoy) generato dal sistema di detection.\n"
    "Non contiene dati reali. Qualsiasi modifica a questo file genera un alert.\n"
) * 40  # dimensione plausibile, non banale (evita match troppo facili su "file vuoto")

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "..", "storage", "decoy_manifest.json")


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def plant_decoys(target_dir, count=8):
    """Crea `count` file civetta dentro target_dir e salva il manifest (path -> hash)."""
    os.makedirs(target_dir, exist_ok=True)
    names = random.sample(DECOY_NAMES, min(count, len(DECOY_NAMES)))
    manifest = {}
    for name in names:
        path = os.path.join(target_dir, name)
        with open(path, "w") as f:
            f.write(FILLER_TEXT)
        manifest[os.path.abspath(path)] = {
            "hash": _sha256(path),
            "size": os.path.getsize(path),
        }
    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def load_manifest():
    if not os.path.exists(MANIFEST_PATH):
        return {}
    with open(MANIFEST_PATH) as f:
        return json.load(f)


def is_decoy(path):
    manifest = load_manifest()
    return os.path.abspath(path) in manifest


def verify_decoy(path):
    """Ritorna True se il decoy risulta ancora integro (hash invariato)."""
    manifest = load_manifest()
    key = os.path.abspath(path)
    if key not in manifest:
        return None  # non è un decoy noto
    if not os.path.exists(path):
        return False  # cancellato -> compromesso
    try:
        return _sha256(path) == manifest[key]["hash"]
    except Exception:
        return False


if __name__ == "__main__":
    target = os.path.join(os.path.dirname(__file__), "..", "honeypot")
    m = plant_decoys(target)
    print(f"Piantati {len(m)} file civetta in {os.path.abspath(target)}")
    for p in m:
        print("  -", p)
