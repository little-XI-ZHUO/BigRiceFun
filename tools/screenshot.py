"""Capture the BigRiceScan window to docs/screenshot-main.png (Windows).

Finds the visible top-level window whose title contains "BigRiceScan", moves it fully onto
the primary screen, and copies that screen region into a PNG.

usage: python -I tools/screenshot.py <out.png> [title]
"""
import ctypes
import ctypes.wintypes as wt
import sys

from PIL import ImageGrab

user32 = ctypes.windll.user32
user32.SetProcessDPIAware()

EnumWindowsProc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def find_window(pid, needle):
    found = []

    def cb(hwnd, _):
        p = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if p.value == pid and user32.IsWindowVisible(hwnd):
            n = user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(hwnd, buf, n + 1)
            if needle in buf.value:
                found.append((hwnd, buf.value))
        return True

    user32.EnumWindows(EnumWindowsProc(cb), 0)
    return found


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "docs/screenshot-main.png"
    needle = sys.argv[2] if len(sys.argv) > 2 else "BigRiceScan"
    pid = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    cands = find_window(pid, needle) if pid else []
    if not cands:
        # fall back to any visible window with that title
        for h in range(0):
            pass
        import subprocess
        out_text = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-Process | Where-Object { $_.MainWindowTitle -like '*%s*' } | "
             "ForEach-Object { $_.Id }" % needle],
            capture_output=True).stdout.decode("utf-8", "replace").split()
        for p in out_text:
            try:
                cands = find_window(int(p), needle)
                if cands:
                    break
            except ValueError:
                pass
    if not cands:
        raise SystemExit("window with title containing %r not found" % needle)

    hwnd, title = cands[0]
    # move it fully onto the screen, then read back the real bounds
    user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0001 | 0x0004)  # NOSIZE|NOMOVE
    rect = wt.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    w, h = rect.right - rect.left, rect.bottom - rect.top
    scr_w = user32.GetSystemMetrics(0)
    scr_h = user32.GetSystemMetrics(1)
    if w > scr_w - 8 or h > scr_h - 8:
        user32.MoveWindow(hwnd, 0, 0, scr_w - 8, scr_h - 8, True)
        import time
        time.sleep(1.0)
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
    left, top = rect.left, rect.top
    w, h = rect.right - left, rect.bottom - top
    img = ImageGrab.grab(bbox=(left, top, left + w, top + h), all_screens=True)
    img.save(out)
    print("captured %r -> %s  %dx%d at (%d,%d)" % (title, out, w, h, left, top))


if __name__ == "__main__":
    main()
