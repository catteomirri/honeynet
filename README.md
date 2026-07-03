# Ransomware Detection & Containment Engine

Honeynet di laboratorio per rilevare comportamenti tipici di ransomware
(cifratura di massa, tocco di file esca) tramite File Integrity Monitoring,
con contenimento automatico e dashboard di analisi/replay.

## Come funziona

1. **`agent/decoy_manager.py`** pianta file "civetta" con nomi appetibili
   (`Fatture_2024.xlsx`, `Password_Aziendali.docx`, ecc.) nella cartella
   `honeypot/` e ne salva l'hash SHA-256 di baseline.
2. **`agent/fim_watcher.py`** osserva `honeypot/` in tempo reale (libreria
   `watchdog`). Per ogni evento calcola l'entropia di Shannon del contenuto
   (i file cifrati hanno entropia vicina a 8 bit/byte) e prova a
   identificare il processo responsabile via `/proc`.
3. **`agent/detection_engine.py`** assegna uno score a ogni evento
   combinando: file civetta toccato, entropia alta, estensione sospetta
   (`.locked`, `.encrypted`, ecc.), velocità di modifica (burst). Sopra
   soglia genera un **alert**; sopra soglia più alta apre un **incidente**.
4. **`agent/containment.py`** al momento dell'apertura di un incidente esegue
   il playbook di risposta: kill del processo, isolamento di rete,
   disconnessione condivisioni, quarantena della cartella colpita.
   **Di default gira in `dry_run=True`**: logga cosa farebbe senza eseguirlo
   davvero — sicuro per un laboratorio.
5. **`dashboard/`** (Flask) espone API REST e una console web con stream
   eventi live, alert, elenco incidenti e **replay** timeline di ogni
   incidente.
6. **`simulator/ransomware_sim.py`** genera un attacco di test *benigno*:
   opera solo dentro `honeypot/`, con una trasformazione XOR reversibile
   (non crittografia reale) solo per alzare l'entropia e cambiare
   l'estensione dei file, così da far scattare il detector in modo realistico.

## Avvio
source venv/bin/activate nel caso 
```bash
cd ransomware-honeynet
pip install -r requirements.txt   # watchdog, flask

python3 main.py
```

Apri **http://127.0.0.1:5050** per la dashboard.

In un secondo terminale, genera un attacco di test:

```bash
python3 simulator/ransomware_sim.py
```

Vedrai in tempo reale: eventi FIM nello stream, alert che si accendono,
incidente che si apre, badge di stato che passa a "contained", e potrai
premere **Replay** sull'incidente per rivedere la timeline esatta
dell'attacco (utile per analisi forense post-incidente).

## Passare dal laboratorio a un uso più realistico

- **Contenimento reale**: `ContainmentManager(dry_run=False, network_interface="eth0")`
  in `main.py`. Farlo **solo** in una VM/container isolato dedicato al test:
  `isolate_host` applica regole `iptables` che bloccano il traffico in uscita.
- **Monitorare cartelle reali** (non solo `honeypot/`): aggiungi altri path
  alla lista passata a `start_watching()` in `main.py`. Su condivisioni di
  rete reali, pianta decoy anche lì con `decoy_manager.plant_decoys(path)`.
- **Tuning soglie**: `ENTROPY_THRESHOLD`, `RATE_THRESHOLD`,
  `SCORE_THRESHOLD_ALERT/INCIDENT` in `agent/detection_engine.py` — vanno
  calibrate sul traffico reale dell'ambiente per ridurre falsi positivi.
- **Identificazione processo**: `find_responsible_process` in
  `fim_watcher.py` è best-effort via `/proc`; in produzione conviene un
  hook a livello kernel (es. eBPF) per un'attribuzione più affidabile.
- **Persistenza**: sostituire SQLite con Postgres se il volume di eventi
  cresce, e aggiungere autenticazione alla dashboard prima di esporla oltre
  `127.0.0.1`.

## Struttura

```
ransomware-honeynet/
├── agent/
│   ├── decoy_manager.py
│   ├── fim_watcher.py
│   ├── detection_engine.py
│   └── containment.py
├── simulator/
│   └── ransomware_sim.py
├── dashboard/
│   ├── app.py
│   └── templates/index.html
├── storage/
│   └── db.py
├── honeypot/           # popolata a runtime dai file civetta
└── main.py
```
