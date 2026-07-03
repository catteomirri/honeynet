"""
agent/fim_watcher.py
File Integrity Monitor basato su `watchdog`. Osserva la cartella honeypot
(e opzionalmente altre cartelle "reali" di test) e per ogni evento:
  - calcola entropia di Shannon del contenuto (i file cifrati hanno entropia alta, ~7.9-8.0 bit/byte)
  - verifica se il file è un decoy noto
  - identifica il processo responsabile (best-effort, via /proc su Linux)
  - inoltra l'evento al detection engine
"""
import os
import sys
import math
import time
import glob
from collections import Counter
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from storage import db
from agent import decoy_manager
from agent.detection_engine import DetectionEngine


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy  # 0 (uniforme/vuoto) .. 8 (massima casualità, tipico di dati cifrati/compressi)


def find_responsible_process(filepath):
    """
    Best-effort: cerca tra /proc/*/fd quale processo ha attualmente
    un file descriptor aperto su un file nella stessa cartella.
    Non è garantito trovarlo (la scrittura potrebbe essere già conclusa),
    ma su un attacco in corso con centinaia di file è statisticamente efficace.
    """
    target_dir = os.path.dirname(os.path.abspath(filepath))
    try:
        for pid_dir in glob.glob("/proc/[0-9]*"):
            pid = os.path.basename(pid_dir)
            fd_dir = os.path.join(pid_dir, "fd")
            try:
                for fd in os.listdir(fd_dir):
                    link = os.readlink(os.path.join(fd_dir, fd))
                    if link.startswith(target_dir):
                        try:
                            with open(os.path.join(pid_dir, "comm")) as f:
                                name = f.read().strip()
                        except Exception:
                            name = "unknown"
                        return int(pid), name
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue
    except Exception:
        pass
    return None, None


class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self, engine: DetectionEngine):
        self.engine = engine

    def _read_sample(self, path, max_bytes=65536):
        try:
            with open(path, "rb") as f:
                return f.read(max_bytes)
        except Exception:
            return b""

    def _handle(self, event_type, src_path, dest_path=None):
        path = dest_path or src_path
        if event_type != "deleted" and os.path.isdir(path):
            return  # ignoriamo eventi sulle directory stesse

        entropy = None
        size = None
        if event_type != "deleted" and os.path.exists(path):
            data = self._read_sample(path)
            entropy = round(shannon_entropy(data), 3)
            size = os.path.getsize(path)

        extension = os.path.splitext(path)[1]
        decoy = decoy_manager.is_decoy(src_path) or decoy_manager.is_decoy(path)
        pid, pname = find_responsible_process(path)

        eid = db.insert_event(
            event_type=event_type, path=path, is_decoy=decoy,
            entropy=entropy, size=size, extension=extension,
            pid=pid, process_name=pname,
        )

        self.engine.process_event({
            "id": eid, "ts": time.time(), "event_type": event_type, "path": path,
            "is_decoy": decoy, "entropy": entropy, "size": size,
            "extension": extension, "pid": pid, "process_name": pname,
        })

    def on_created(self, event):
        if not event.is_directory:
            self._handle("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._handle("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._handle("moved", event.src_path, dest_path=event.dest_path)


def start_watching(paths, engine: DetectionEngine):
    observer = Observer()
    handler = RansomwareEventHandler(engine)
    for p in paths:
        os.makedirs(p, exist_ok=True)
        observer.schedule(handler, p, recursive=True)
    observer.start()
    return observer


if __name__ == "__main__":
    db.init_db()
    engine = DetectionEngine()
    honeypot = os.path.join(os.path.dirname(__file__), "..", "honeypot")
    obs = start_watching([honeypot], engine)
    print(f"FIM attivo su {os.path.abspath(honeypot)}. CTRL+C per fermare.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        obs.stop()
    obs.join()
