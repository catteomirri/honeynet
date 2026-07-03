"""
simulator/ransomware_sim.py

Harness di TEST per generare comportamento realistico di ransomware e
verificare che il sistema di detection lo rilevi. Ispirato a tool reali
come RanSim/Atomic Red Team, usati dai team di sicurezza per validare EDR.

Vincoli di sicurezza volutamente rigidi:
  - opera ESCLUSIVAMENTE dentro la cartella passata come argomento
  - si rifiuta di girare se il path non è dentro la cartella "honeypot/" del progetto
  - usa un XOR banale reversibile (NON crittografia reale) solo per alzare
    l'entropia dei file e cambiarne l'estensione, sufficiente a far scattare
    il detection engine, senza fornire codice di cifratura riutilizzabile
  - non si propaga, non cerca altri file sul sistema, non ha persistenza,
    non comunica in rete
"""
import os
import sys
import time
import argparse

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ALLOWED_ROOT = os.path.join(PROJECT_ROOT, "honeypot")


def _toy_transform(data: bytes, key: int = 0x5A) -> bytes:
    """Trasformazione reversibile banale, solo per alzare l'entropia in modo realistico."""
    return bytes(b ^ key for b in data)


def simulate_attack(target_dir, delay=0.3, new_ext=".locked"):
    target_dir = os.path.abspath(target_dir)
    if not target_dir.startswith(ALLOWED_ROOT):
        print(f"RIFIUTATO: il simulatore può operare solo dentro {ALLOWED_ROOT}")
        sys.exit(1)
    if not os.path.isdir(target_dir):
        print(f"Cartella non trovata: {target_dir}")
        sys.exit(1)

    files = [os.path.join(target_dir, f) for f in os.listdir(target_dir)
             if os.path.isfile(os.path.join(target_dir, f))]

    print(f"[SIM] Avvio simulazione attacco su {len(files)} file in {target_dir}")
    for path in files:
        try:
            with open(path, "rb") as f:
                data = f.read()
            transformed = _toy_transform(data)
            new_path = path + new_ext
            with open(new_path, "wb") as f:
                f.write(transformed)
            os.remove(path)
            print(f"[SIM]   cifrato (simulato): {os.path.basename(path)} -> {os.path.basename(new_path)}")
        except Exception as e:
            print(f"[SIM]   errore su {path}: {e}")
        time.sleep(delay)  # simula la cadenza di scrittura di un ransomware reale

    print("[SIM] Simulazione completata.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulatore benigno di attacco ransomware per test del detector")
    parser.add_argument("--target", default=ALLOWED_ROOT, help="Cartella honeypot da attaccare")
    parser.add_argument("--delay", type=float, default=0.3, help="Secondi tra un file e l'altro")
    args = parser.parse_args()
    simulate_attack(args.target, delay=args.delay)
