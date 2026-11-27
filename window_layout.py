"""DPI-bewusste Anordnung klassischer Windows-Konsolen; best effort."""

import ctypes
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def _message_api():
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.PeekMessageW.argtypes = [
        ctypes.POINTER(wintypes.MSG),
        wintypes.HWND,
        wintypes.UINT,
        wintypes.UINT,
        wintypes.UINT,
    ]
    user.PeekMessageW.restype = wintypes.BOOL
    user.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user.DispatchMessageW.restype = wintypes.LPARAM
    return user


def pump_window_messages():
    """Auch beim Konsolen-Polling implizite Windows-Threadfenster bedienen."""
    if os.name != "nt":
        return
    user = _message_api()
    message = wintypes.MSG()
    # Begrenzen, damit Fensterereignisse die Laborsteuerung nicht verdraengen.
    for _ in range(64):
        if not user.PeekMessageW(ctypes.byref(message), None, 0, 0, 1):
            break
        user.TranslateMessage(ctypes.byref(message))
        user.DispatchMessageW(ctypes.byref(message))


def component_command(python_command, layout_file, headless=False):
    """Eigenen klassischen Host verwenden, ohne globale Terminal-Einstellungen zu aendern."""
    if os.name == "nt" and not headless:
        try:
            config = json.loads(Path(layout_file).read_text("utf-8"))
        except (OSError, ValueError):
            config = {}
        host = (
            Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32"
            / "conhost.exe"
        )
        if config.get("console_host") == "classic" and host.is_file():
            return [str(host), *python_command]
    return python_command


def needs_classic_controller(layout_file):
    if os.name != "nt":
        return False
    try:
        config = json.loads(Path(layout_file).read_text("utf-8"))
        if config.get("console_host") != "classic":
            return False
        kernel = ctypes.WinDLL("kernel32")
        user = ctypes.WinDLL("user32")
        kernel.GetConsoleWindow.restype = wintypes.HWND
        user.IsWindowVisible.argtypes = [wintypes.HWND]
        hwnd = kernel.GetConsoleWindow()
        return not hwnd or not user.IsWindowVisible(hwnd)
    except (OSError, ValueError):
        return False


def apply_layout(path, actor):
    if os.name != "nt":
        return False
    try:
        config = json.loads(path.read_text("utf-8"))
        if not config.get("enabled", True):
            return False
        user = ctypes.WinDLL("user32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        try:
            user.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
            user.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        except AttributeError:
            user.SetProcessDPIAware()
        # Ein Host/Manifest kann die Prozess-DPI bereits festgelegt haben.
        # Der Threadkontext verhindert dann skalierte MoveWindow-Koordinaten.
        if hasattr(user, "SetThreadDpiAwarenessContext"):
            user.SetThreadDpiAwarenessContext.argtypes = [ctypes.c_void_p]
            user.SetThreadDpiAwarenessContext.restype = ctypes.c_void_p
            user.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
        kernel.GetConsoleWindow.restype = wintypes.HWND
        hwnd = kernel.GetConsoleWindow()
        user.IsWindowVisible.argtypes = [wintypes.HWND]
        if not hwnd or not user.IsWindowVisible(hwnd):
            raise RuntimeError(
                "Kein eigenes sichtbares klassisches Konsolenfenster (z.B. Windows Terminal)"
            )
        areas = []

        class MonitorInfo(ctypes.Structure):
            _fields_ = [
                ("size", wintypes.DWORD),
                ("monitor", wintypes.RECT),
                ("work", wintypes.RECT),
                ("flags", wintypes.DWORD),
            ]

        callback_type = ctypes.WINFUNCTYPE(
            wintypes.BOOL,
            wintypes.HANDLE,
            wintypes.HDC,
            ctypes.POINTER(wintypes.RECT),
            wintypes.LPARAM,
        )
        user.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MonitorInfo)]

        def collect(monitor, dc, rect, data):
            info = MonitorInfo()
            info.size = ctypes.sizeof(info)
            if user.GetMonitorInfoW(monitor, ctypes.byref(info)):
                r = info.work
                areas.append(
                    (
                        (r.left, r.top, r.right - r.left, r.bottom - r.top),
                        bool(info.flags & 1),
                    )
                )
            return True

        callback = callback_type(collect)
        user.EnumDisplayMonitors(None, None, callback, 0)
        index = config.get("monitor", "primary")
        if index == "primary":
            index = next((i for i, (_, primary) in enumerate(areas) if primary), 0)
        if type(index) is not int or not 0 <= index < len(areas):
            raise ValueError("Monitorindex nicht verfuegbar (Zaehlen beginnt bei 0)")
        left, top, width, height = areas[index][0]
        rectangle = config["windows"][actor]
        if (
            len(rectangle) != 4
            or not all(isinstance(n, (int, float)) for n in rectangle)
            or min(rectangle) < 0
            or rectangle[0] + rectangle[2] > 1.001
            or rectangle[1] + rectangle[3] > 1.001
            or min(rectangle[2:]) <= 0
        ):
            raise ValueError("Fensterrechtecke muessen innerhalb 0..1 liegen")

        class FontInfo(ctypes.Structure):
            _fields_ = [
                ("size", wintypes.ULONG),
                ("index", wintypes.DWORD),
                ("dimensions", wintypes._COORD),
                ("family", wintypes.UINT),
                ("weight", wintypes.UINT),
                ("face", wintypes.WCHAR * 32),
            ]

        kernel.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel.GetStdHandle.restype = wintypes.HANDLE
        output = kernel.GetStdHandle(-11 & 0xFFFFFFFF)
        font = FontInfo()
        font.size = ctypes.sizeof(font)
        font.dimensions.Y = max(
            8,
            min(
                40,
                int(
                    config.get("fonts", {}).get(
                        actor,
                        config.get(
                            "controller_font"
                            if actor == "controller"
                            else "technical_font",
                            18,
                        ),
                    )
                ),
            ),
        )
        font.face = "Consolas"
        kernel.SetCurrentConsoleFontEx.argtypes = [
            wintypes.HANDLE,
            wintypes.BOOL,
            ctypes.POINTER(FontInfo),
        ]
        font_applied = bool(
            kernel.SetCurrentConsoleFontEx(output, False, ctypes.byref(font))
        )
        mode = wintypes.DWORD()
        kernel.GetConsoleMode.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        if kernel.GetConsoleMode(output, ctypes.byref(mode)):
            kernel.SetConsoleMode(
                output, mode.value | 4
            )  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        # QuickEdit kann bei einem einfachen Mausklick die gesamte Ausgabe
        # anhalten. Nur den Modus dieses Konsolenfensters aendern.
        input_handle = kernel.GetStdHandle(-10 & 0xFFFFFFFF)
        if kernel.GetConsoleMode(input_handle, ctypes.byref(mode)):
            kernel.SetConsoleMode(input_handle, (mode.value | 0x80) & ~0x40)
        user.MoveWindow.argtypes = [
            wintypes.HWND,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.BOOL,
        ]
        x, y, w, h = rectangle
        requested = [
            left + int(width * x),
            top + int(height * y),
            int(width * w),
            int(height * h),
        ]
        if not user.MoveWindow(hwnd, *requested, True):
            raise ctypes.WinError(ctypes.get_last_error())
        # conhost verarbeitet die durch den Schriftwechsel ausgeloeste
        # Groessenanpassung asynchron. Erst danach die Endgeometrie setzen.
        time.sleep(0.2)
        user.MoveWindow(hwnd, *requested, True)
        time.sleep(0.1)
        actual = wintypes.RECT()
        user.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        user.GetWindowRect(hwnd, ctypes.byref(actual))
        measured = [
            actual.left,
            actual.top,
            actual.right - actual.left,
            actual.bottom - actual.top,
        ]
        limited = any(abs(a - b) > 20 for a, b in zip(measured, requested))
        from demo_ipc import emit

        emit(
            "layout_limited" if limited else "layout_applied",
            window=actor,
            monitor=index,
            font_applied=font_applied,
            font_height=font.dimensions.Y,
            hwnd=int(hwnd),
            rectangle=measured,
            requested=requested,
            work_area=[left, top, width, height],
            primary=areas[index][1],
        )
        if limited or not font_applied:
            print(
                "[LAYOUT] Konsolenhost begrenzt Groesse/Schrift; Layout oder Host-Schrift manuell anpassen.",
                flush=True,
            )
        return True
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        RuntimeError,
        AttributeError,
    ) as exc:
        print(
            f"[LAYOUT] Automatik nicht verfuegbar: {exc}. "
            "Windows-Konsolenhost verwenden oder Fenster manuell anordnen.",
            flush=True,
        )
        return False


def focus_controller():
    if os.name != "nt":
        return False
    # SetForegroundWindow darf nicht vom dauernd wartenden Steuerthread aus
    # aufgerufen werden: Windows kann dessen Input-Queue mit conhost verbinden.
    # Ohne GUI-Message-Pump reagiert conhost dann nach wenigen Sekunden nicht
    # mehr auf Maus/Titelleiste. Der kurze Helfer loest die Verbindung beim Ende.
    code = (
        "import ctypes; from ctypes import wintypes; "
        "k=ctypes.WinDLL('kernel32'); u=ctypes.WinDLL('user32'); "
        "k.GetConsoleWindow.restype=wintypes.HWND; "
        "u.SetForegroundWindow.argtypes=[wintypes.HWND]; "
        "raise SystemExit(0 if u.SetForegroundWindow(k.GetConsoleWindow()) else 1)"
    )
    try:
        result = (
            subprocess.run(
                [sys.executable, "-c", code],
                timeout=3,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        result = False
    if not result:
        print(
            "[LAB] Zum Bedienen das Steuerfenster anklicken (Terminal-Fokus vom Host begrenzt).",
            flush=True,
        )
    return result
