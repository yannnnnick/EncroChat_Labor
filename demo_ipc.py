"""Optionale Dateiqueues fuer das eigene Labor; keine Netzwerk-IPC."""

import hashlib
import json
import os
import queue
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

LOCK = threading.Lock()


def plugin_label(name):
    """Lesbarer Anzeigename; signierte Paketnamen bleiben unveraendert."""
    return {"dummy": "Standard", "audit": "Audit"}.get(name, name)


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def emit(kind, **data):
    directory = os.environ.get("LAB_DEMO_DIR")
    actor = os.environ.get("LAB_DEMO_ACTOR")
    if not directory or not actor:
        return
    entry = dict(data, event=kind, actor=actor, utc=utc(), event_id=uuid.uuid4().hex)
    path = Path(directory) / "ipc" / (actor + ".jsonl")
    with LOCK, path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def control_worker(stop, callback):
    directory = os.environ.get("LAB_DEMO_DIR")
    actor = os.environ.get("LAB_DEMO_ACTOR")
    if not directory or not actor:
        return
    inbox = Path(directory) / "ipc" / actor
    inbox.mkdir(exist_ok=True)

    def work():
        while not stop.wait(0.04):
            for path in sorted(inbox.glob("*.json")):
                claimed = path.with_suffix(".processing")
                try:
                    path.rename(
                        claimed
                    )  # vor Ausfuehrung beanspruchen, niemals wiederholen
                    command = json.loads(claimed.read_text("utf-8"))
                    result = callback(command)
                    emit("command_done", request_id=path.stem, result=result)
                except Exception as exc:
                    emit(
                        "command_error",
                        request_id=path.stem,
                        reason=f"{type(exc).__name__}: {exc}",
                    )
                finally:
                    if claimed.exists():
                        claimed.rename(claimed.with_suffix(".done"))

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    return thread


def console_lines(stop):
    """Console bleibt bedienbar, IPC-Shutdown haengt nicht in input()."""
    lines = queue.Queue()

    def read():
        try:
            while not stop.is_set():
                lines.put(input("config> "))
        except (EOFError, KeyboardInterrupt):
            lines.put(None)

    threading.Thread(target=read, daemon=True).start()
    while not stop.is_set():
        try:
            line = lines.get(timeout=0.1)
        except queue.Empty:
            continue
        if line is None:
            return
        yield line
