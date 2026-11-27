"""Anordnung in einem echten separaten Windows-Konsolenfenster messen."""

import ctypes
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from ctypes import wintypes
from pathlib import Path

from demo_controller import new_results
from start_lab import ROOT, WindowsJob
from window_layout import component_command


@unittest.skipUnless(os.name == "nt", "Windows-Konsolenlayout")
class LayoutTest(unittest.TestCase):
    def test_controller_still_handles_mouse_messages_after_focus_and_idle(self):
        with tempfile.TemporaryDirectory(prefix="demo-test-", dir=ROOT) as root:
            directory = new_results(root)
            env = os.environ.copy()
            env.update(LAB_DEMO_DIR=str(directory), LAB_DEMO_ACTOR="controller")
            code = (
                "from pathlib import Path; import time; "
                "from window_layout import apply_layout,focus_controller,pump_window_messages; from demo_ipc import emit; "
                "apply_layout(Path('window_layout.json'),'controller'); "
                "focus_controller(); emit('focus_finished');\n"
                "import msvcrt\nfor _ in range(150):\n pump_window_messages()\n msvcrt.kbhit()\n time.sleep(0.1)"
            )
            command = component_command(
                [sys.executable, "-X", "utf8", "-c", code], ROOT / "window_layout.json"
            )
            with WindowsJob() as job:
                process = subprocess.Popen(
                    command,
                    cwd=ROOT,
                    env=env,
                    creationflags=subprocess.CREATE_NEW_CONSOLE | 4,
                )
                job.attach(process)
                job.resume(process)
                path = directory / "ipc" / "controller.jsonl"
                deadline = time.monotonic() + 8
                while True:
                    events = (
                        [
                            json.loads(line)
                            for line in path.read_text("utf-8").splitlines()
                        ]
                        if path.exists()
                        else []
                    )
                    if any(e["event"] == "focus_finished" for e in events):
                        break
                    self.assertLess(time.monotonic(), deadline, "Fokus-Helfer haengt")
                    time.sleep(0.05)
                layout = next(e for e in events if e["event"] == "layout_applied")
                time.sleep(6)  # Fehler trat erst nach etwa fuenf Sekunden auf.
                user = ctypes.WinDLL("user32", use_last_error=True)
                user.SendMessageTimeoutW.argtypes = [
                    wintypes.HWND,
                    wintypes.UINT,
                    wintypes.WPARAM,
                    wintypes.LPARAM,
                    wintypes.UINT,
                    wintypes.UINT,
                    ctypes.POINTER(ctypes.c_size_t),
                ]
                user.SendMessageTimeoutW.restype = wintypes.LPARAM
                answer = ctypes.c_size_t()
                x, y, width, height = layout["rectangle"]
                point = ((y + 12) & 0xFFFF) << 16 | ((x + width // 2) & 0xFFFF)
                # WM_NCHITTEST prueft genau den Mauspfad fuer Titelleiste/Rand.
                self.assertTrue(
                    user.SendMessageTimeoutW(
                        layout["hwnd"], 0x84, 0, point, 3, 800, ctypes.byref(answer)
                    ),
                    "Konsolenfenster verarbeitet keine Mausnachrichten mehr",
                )
                self.assertEqual(
                    answer.value,
                    2,
                    "Titelleiste muss als verschiebbar erkannt werden (HTCAPTION)",
                )
                self.assertGreaterEqual(layout["font_height"], 18)
                area = layout["work_area"]
                self.assertAlmostEqual(x + width / 2, area[0] + area[2] / 2, delta=20)
                self.assertAlmostEqual(y + height / 2, area[1] + area[3] / 2, delta=20)
                job.terminate()
                process.wait(timeout=5)

    def test_real_console_rectangle_and_font(self):
        with tempfile.TemporaryDirectory(prefix="demo-test-", dir=ROOT) as root:
            directory = new_results(root)
            with WindowsJob() as job:
                children = []
                for actor in (
                    "controller",
                    "client_1",
                    "client_2",
                    "routing_server",
                    "config_server",
                    "audit_collector",
                ):
                    env = os.environ.copy()
                    env.update(LAB_DEMO_DIR=str(directory), LAB_DEMO_ACTOR=actor)
                    env.pop("LAB_TLS_KEYLOG", None)
                    env.pop("SSLKEYLOGFILE", None)
                    code = (
                        "from pathlib import Path; import time,sys; from window_layout import apply_layout; "
                        "ok=apply_layout(Path('window_layout.json'),sys.argv[1]); time.sleep(3); "
                        "raise SystemExit(0 if ok else 9)"
                    )
                    command = component_command(
                        [sys.executable, "-X", "utf8", "-c", code, actor],
                        ROOT / "window_layout.json",
                    )
                    self.assertEqual(Path(command[0]).name.lower(), "conhost.exe")
                    p = subprocess.Popen(
                        command,
                        cwd=ROOT,
                        env=env,
                        creationflags=subprocess.CREATE_NEW_CONSOLE | 4,
                    )
                    children.append(p)
                    job.attach(p)
                    job.resume(p)
                for p in children:
                    self.assertEqual(p.wait(timeout=15), 0)
            events = [
                json.loads(line)
                for path in (directory / "ipc").glob("*.jsonl")
                for line in path.read_text("utf-8").splitlines()
            ]
            self.assertEqual(len(events), 6)
            self.assertEqual(len({tuple(e["rectangle"]) for e in events}), 6)
            for event in events:
                self.assertTrue(event["font_applied"])
                self.assertTrue(event["primary"])
                self.assertEqual(event["event"], "layout_applied")
                self.assertTrue(
                    all(
                        abs(a - b) <= 20
                        for a, b in zip(event["rectangle"], event["requested"])
                    ),
                    {
                        k: event[k]
                        for k in ("window", "rectangle", "requested", "work_area")
                    },
                )
