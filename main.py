"""
main.py
Punto di ingresso del laboratorio. Avvia in un unico processo:
  1. inizializzazione del DB
  2. piantumazione dei file civetta nella cartella honeypot/
  3. detection engine + containment manager (in DRY-RUN, sicuro per il lab)
  4. FIM watcher su honeypot/
  5. dashboard web su http://127.0.0.1:5050
"""
import os
import sys
import threading

sys.path.append(os.path.dirname(__file__))

from storage import db
from agent import decoy_manager
from agent.detection_engine import DetectionEngine
from agent.containment import ContainmentManager
from agent.fim_watcher import start_watching

HONEYPOT_DIR = os.path.join(os.path.dirname(__file__), "honeypot")


def main():
    print("=" * 60)
    print(" RANSOMWARE HONEYNET — laboratorio di detection e contenimento")
    print("=" * 60)

    db.init_db()
    db.reset_db()

    manifest = decoy_manager.plant_decoys(HONEYPOT_DIR, count=8)
    print(f"[+] {len(manifest)} file civetta piantati in {HONEYPOT_DIR}")

    containment = ContainmentManager(dry_run=True)  # sicuro di default per il lab
    engine = DetectionEngine(containment=containment)

    observer = start_watching([HONEYPOT_DIR], engine)
    print(f"[+] FIM attivo su {HONEYPOT_DIR}")

    from dashboard.app import app
    print("[+] Dashboard disponibile su http://127.0.0.1:5050")
    print()
    print("Per generare un attacco di test, in un altro terminale esegui:")
    print("    python3 simulator/ransomware_sim.py")
    print()

    try:
        app.run(host="127.0.0.1", port=5050, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
