"""
agent/detection_engine.py
Riceve il flusso di eventi dal FIM e decide se costituiscono un attacco.

Euristiche combinate (tipiche degli EDR reali):
  1. DECOY HIT      -> qualsiasi tocco a un file civetta = altissima confidenza da solo
  2. ENTROPIA ALTA  -> contenuto vicino alla casualità massima = probabile cifratura
  3. ESTENSIONI SOSPETTE -> .locked, .encrypted, .crypt, .enc, ecc.
  4. VELOCITA'      -> tante modifiche in poco tempo nella stessa cartella = comportamento
                        automatizzato/di massa, non umano
Lo score è cumulativo; oltre soglia si apre un incidente e si attiva il contenimento.
"""
import time
import os
import sys
from collections import deque

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from storage import db

SUSPICIOUS_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".enc", ".ransom", ".crypted",
    ".locky", ".cerber", ".zzz", ".micro", ".xyz", ".vault",
}

ENTROPY_THRESHOLD = 7.5          # su una scala 0-8
RATE_WINDOW_SECONDS = 5          # finestra temporale per il conteggio eventi
RATE_THRESHOLD = 10              # eventi nella finestra per considerarli "burst"
SCORE_THRESHOLD_ALERT = 40       # soglia per generare un alert
SCORE_THRESHOLD_INCIDENT = 70    # soglia per aprire un incidente + contenimento


class DetectionEngine:
    def __init__(self, containment=None):
        self.recent_events = deque(maxlen=500)   # per il calcolo del rate
        self.active_incident_id = None
        self.incident_score = 0
        self.last_event_ts = 0
        self.containment = containment  # istanza di ContainmentManager, iniettata dall'orchestratore

    # ---- scoring dei singoli eventi -------------------------------------------------
    def _score_event(self, event):
        score = 0
        reasons = []

        if event["is_decoy"] and event["event_type"] in ("modified", "deleted", "moved"):
            score += 60
            reasons.append("file civetta modificato/cancellato")

        if event.get("entropy") is not None and event["entropy"] >= ENTROPY_THRESHOLD:
            score += 25
            reasons.append(f"entropia elevata ({event['entropy']}/8.0)")

        ext = (event.get("extension") or "").lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            score += 20
            reasons.append(f"estensione sospetta ({ext})")

        return score, reasons

    def _rate_score(self):
        now = time.time()
        recent = [e for e in self.recent_events if now - e["ts"] <= RATE_WINDOW_SECONDS]
        if len(recent) >= RATE_THRESHOLD:
            return 30, [f"{len(recent)} eventi in {RATE_WINDOW_SECONDS}s (burst automatizzato)"]
        return 0, []

    # ---- entry point chiamato dal FIM watcher ----------------------------------------
    def process_event(self, event):
        self.recent_events.append(event)

        ev_score, ev_reasons = self._score_event(event)
        rate_score, rate_reasons = self._rate_score()
        total = ev_score + rate_score
        reasons = ev_reasons + rate_reasons

        if total == 0:
            return

        if total >= SCORE_THRESHOLD_ALERT:
            severity = "critical" if total >= SCORE_THRESHOLD_INCIDENT else "high"
            aid = db.insert_alert(
                severity=severity,
                reason="; ".join(reasons),
                event_ids=[event["id"]],
                incident_id=self.active_incident_id,
            )
            print(f"[ALERT][{severity.upper()}] {reasons} (score={total}) -> {event['path']}")

        self.incident_score += total

        if self.incident_score >= SCORE_THRESHOLD_INCIDENT:
            self._escalate(event, reasons, total)

    def _escalate(self, event, reasons, total):
        is_new_incident = self.active_incident_id is None
        if is_new_incident:
            self.active_incident_id = db.open_incident(
                summary=f"Comportamento ransomware rilevato: {', '.join(reasons)}"
            )
            print(f"\n*** INCIDENTE #{self.active_incident_id} APERTO *** (score cumulativo={self.incident_score})")

        # Il playbook di contenimento (isolamento, kill, quarantena) scatta UNA
        # sola volta all'apertura dell'incidente, non ad ogni singolo evento
        # che continua a superare la soglia (altrimenti spam di azioni identiche).
        if self.containment and is_new_incident:
            self.containment.trigger(self.active_incident_id, event, reasons)

    def reset(self):
        """Chiude l'incidente corrente e azzera lo score (fine demo / dopo bonifica)."""
        if self.active_incident_id:
            db.update_incident(self.active_incident_id, status="resolved")
        self.active_incident_id = None
        self.incident_score = 0
        self.recent_events.clear()
