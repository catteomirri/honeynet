"""
agent/containment.py
Azioni di risposta automatica quando il detection engine apre un incidente.

SICUREZZA: di default gira in DRY_RUN = True, cioè LOGGA le azioni che
farebbe senza eseguirle davvero (niente kill di processi reali, niente
regole firewall). Questo evita che un test in laboratorio uccida
accidentalmente processi legittimi o isoli la macchina da cui stai lavorando.

Per abilitare le azioni reali: ContainmentManager(dry_run=False).
Consigliato SOLO dentro una VM/container isolato dedicato al test.
"""
import os
import sys
import signal
import subprocess
import time

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from storage import db


class ContainmentManager:
    def __init__(self, dry_run=True, network_interface=None):
        self.dry_run = dry_run
        self.network_interface = network_interface  # es. "eth0", solo se dry_run=False
        self.actions_log = []

    def _log_action(self, incident_id, action, detail):
        entry = {"ts": time.time(), "action": action, "detail": detail, "dry_run": self.dry_run}
        self.actions_log.append(entry)
        prefix = "[DRY-RUN] " if self.dry_run else "[ESEGUITO] "
        print(f"{prefix}{action}: {detail}")
        return entry

    def kill_process(self, incident_id, pid, pname):
        detail = f"terminazione processo {pname} (pid={pid})"
        if self.dry_run:
            return self._log_action(incident_id, "kill_process", detail + " [simulato]")
        try:
            os.kill(pid, signal.SIGKILL)
            return self._log_action(incident_id, "kill_process", detail + " [OK]")
        except Exception as e:
            return self._log_action(incident_id, "kill_process", detail + f" [FALLITO: {e}]")

    def isolate_host(self, incident_id):
        """
        Isolamento di rete: in un ambiente reale, blocca tutto il traffico
        tranne verso l'host di gestione (via iptables) o disabilita l'interfaccia.
        """
        detail = f"isolamento rete (interfaccia={self.network_interface or 'auto'})"
        if self.dry_run:
            return self._log_action(incident_id, "isolate_host", detail + " [simulato]")
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "OUTPUT", "-j", "DROP"],
                check=True, timeout=5
            )
            return self._log_action(incident_id, "isolate_host", detail + " [OK]")
        except Exception as e:
            return self._log_action(incident_id, "isolate_host", detail + f" [FALLITO: {e}]")

    def disable_network_shares(self, incident_id, mount_points=None):
        detail = f"disconnessione condivisioni di rete ({mount_points or 'tutte'})"
        if self.dry_run:
            return self._log_action(incident_id, "disable_network_shares", detail + " [simulato]")
        results = []
        for mp in (mount_points or []):
            try:
                subprocess.run(["sudo", "umount", "-f", mp], check=True, timeout=5)
                results.append(f"{mp}: OK")
            except Exception as e:
                results.append(f"{mp}: FALLITO ({e})")
        return self._log_action(incident_id, "disable_network_shares", "; ".join(results) or "nessun mount specificato")

    def quarantine_decoy_folder(self, incident_id, folder):
        """Rende la cartella colpita di sola lettura, per congelare l'evidenza forense."""
        detail = f"quarantena cartella {folder} (chmod 444)"
        if self.dry_run:
            return self._log_action(incident_id, "quarantine_folder", detail + " [simulato]")
        try:
            for root, _, files in os.walk(folder):
                for f in files:
                    os.chmod(os.path.join(root, f), 0o444)
            return self._log_action(incident_id, "quarantine_folder", detail + " [OK]")
        except Exception as e:
            return self._log_action(incident_id, "quarantine_folder", detail + f" [FALLITO: {e}]")

    def trigger(self, incident_id, event, reasons):
        """Orchestrazione: playbook di risposta standard per un incidente ransomware."""
        actions = []
        if event.get("pid"):
            actions.append(self.kill_process(incident_id, event["pid"], event.get("process_name")))
        actions.append(self.isolate_host(incident_id))
        actions.append(self.disable_network_shares(incident_id))
        actions.append(self.quarantine_decoy_folder(incident_id, os.path.dirname(event["path"])))

        db.update_incident(
            incident_id,
            status="contained",
            containment_actions=[a["action"] + ": " + a["detail"] for a in actions],
        )
        return actions
