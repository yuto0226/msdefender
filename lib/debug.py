"""Lightweight debug/logging helpers with ANSI colors and hexdump."""

from __future__ import annotations

import ctypes
import inspect
import os
import sys
from typing import Any


# Colors
ANSI_RESET = "\x1b[0m"
ANSI_RESET_FG = "\x1b[39m"
ANSI_RESET_BG = "\x1b[49m"

ANSI_BOLD = "\x1b[1m"
ANSI_FAINT = "\x1b[2m"
ANSI_ITALIC = "\x1b[3m"
ANSI_UNDERLINE = "\x1b[4m"
ANSI_BLINK = "\x1b[5m"
ANSI_RAPID_BLINK = "\x1b[6m"
ANSI_REVERSE = "\x1b[7m"
ANSI_HIDDEN = "\x1b[8m"
ANSI_STRIKE = "\x1b[9m"
ANSI_DOUBLE_UNDERLINE = "\x1b[21m"

ANSI_BOLD_OFF = "\x1b[22m"
ANSI_FAINT_OFF = "\x1b[22m"
ANSI_ITALIC_OFF = "\x1b[23m"
ANSI_UNDERLINE_OFF = "\x1b[24m"
ANSI_BLINK_OFF = "\x1b[25m"
ANSI_REVERSE_OFF = "\x1b[27m"
ANSI_HIDDEN_OFF = "\x1b[28m"
ANSI_STRIKE_OFF = "\x1b[29m"

ANSI_BLACK = "\x1b[30m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_BLUE = "\x1b[34m"
ANSI_MAGENTA = "\x1b[35m"
ANSI_CYAN = "\x1b[36m"
ANSI_WHITE = "\x1b[37m"
ANSI_DEFAULT_FG = "\x1b[39m"

ANSI_BBLACK = "\x1b[90m"
ANSI_GRAY = "\x1b[90m"
ANSI_GREY = "\x1b[90m"
ANSI_BRED = "\x1b[91m"
ANSI_BGREEN = "\x1b[92m"
ANSI_BYELLOW = "\x1b[93m"
ANSI_BBLUE = "\x1b[94m"
ANSI_BMAGENTA = "\x1b[95m"
ANSI_BCYAN = "\x1b[96m"
ANSI_BWHITE = "\x1b[97m"

ANSI_BG_BLACK = "\x1b[40m"
ANSI_BG_RED = "\x1b[41m"
ANSI_BG_GREEN = "\x1b[42m"
ANSI_BG_YELLOW = "\x1b[43m"
ANSI_BG_BLUE = "\x1b[44m"
ANSI_BG_MAGENTA = "\x1b[45m"
ANSI_BG_CYAN = "\x1b[46m"
ANSI_BG_WHITE = "\x1b[47m"
ANSI_DEFAULT_BG = "\x1b[49m"

ANSI_BG_BBLACK = "\x1b[100m"
ANSI_BG_GRAY = "\x1b[100m"
ANSI_BG_GREY = "\x1b[100m"
ANSI_BG_BRED = "\x1b[101m"
ANSI_BG_BGREEN = "\x1b[102m"
ANSI_BG_BYELLOW = "\x1b[103m"
ANSI_BG_BBLUE = "\x1b[104m"
ANSI_BG_BMAGENTA = "\x1b[105m"
ANSI_BG_BCYAN = "\x1b[106m"
ANSI_BG_BWHITE = "\x1b[107m"


def ANSI_FG_256(n: int) -> str:
    return f"\x1b[38;5;{n}m"


def ANSI_BG_256(n: int) -> str:
    return f"\x1b[48;5;{n}m"


def ANSI_FG_RGB(r: int, g: int, b: int) -> str:
    return f"\x1b[38;2;{r};{g};{b}m"


def ANSI_BG_RGB(r: int, g: int, b: int) -> str:
    return f"\x1b[48;2;{r};{g};{b}m"


def ANSI_WITH(style: str, text: str) -> str:
    return f"{style}{text}{ANSI_RESET}"


def _enable_windows_vt() -> None:
    if os.name != "nt":
        return
    kernel32 = ctypes.windll.kernel32
    h_stdout = kernel32.GetStdHandle(-11)
    h_stderr = kernel32.GetStdHandle(-12)
    mode = ctypes.c_uint()
    enable_vt = 0x0004

    for handle in (h_stdout, h_stderr):
        if handle == 0 or handle == -1:
            continue
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | enable_vt)


_enable_windows_vt()


# Logging
def _fmt_message(fmt: str, args: tuple[Any, ...]) -> str:
    if not args:
        return str(fmt)
    try:
        return fmt % args
    except Exception:
        return "<format error>"


def log(
    fmt: str,
    *args: Any,
    symbol: str = "[i]",
    color: str = ANSI_BLUE,
    to_err: bool = False,
    template: str = "{symbol} {context}\n",
) -> None:
    context = _fmt_message(fmt, args)
    symbol += ANSI_RESET
    try:
        rendered = template.format(symbol=symbol, context=context)
    except Exception:
        rendered = f"{symbol} {context}\n"

    if not rendered.endswith("\n"):
        rendered += "\n"

    payload = rendered[:-1]
    stream = sys.stderr if to_err else sys.stdout
    stream.write(f"{color}{payload}{ANSI_RESET}\n")
    stream.flush()


def panic(fmt: str, *args: Any) -> None:
    frame = inspect.currentframe()
    caller = frame.f_back if frame and frame.f_back else None
    func_name = caller.f_code.co_name if caller else "<unknown>"
    file_name = caller.f_code.co_filename if caller else "<unknown>"
    line_no = caller.f_lineno if caller else 0

    err_no = ctypes.get_errno()
    err_msg = os.strerror(err_no) if err_no else "Success"
    msg = _fmt_message(fmt, args)

    sys.stderr.write(f"{ANSI_RED}[x] [{func_name}] {msg} ")
    sys.stderr.write(f"(errno={err_no}: {err_msg}) {file_name}:{line_no}{ANSI_RESET}\n")
    sys.stderr.flush()
    raise SystemExit(1)


def error(fmt: str, *args: Any) -> None:
    log(fmt, *args, symbol="[-]", color=ANSI_RED, to_err=True)


def warn(fmt: str, *args: Any) -> None:
    log(fmt, *args, symbol="[!]", color=ANSI_YELLOW, to_err=True)


def info(fmt: str, *args: Any) -> None:
    log(fmt, *args, symbol="[i]", color=ANSI_BLUE)


def ok(fmt: str, *args: Any) -> None:
    log(fmt, *args, symbol="[+]", color=ANSI_GREEN)


def debug(fmt: str, *args: Any) -> None:
    log(fmt, *args, symbol="[d]", color=ANSI_CYAN)


# Helper
def hexdump(buf: bytes | bytearray | memoryview, size: int | None = None) -> None:
    data = memoryview(buf).cast("B")
    if size is None or size > len(data):
        size = len(data)

    for off in range(0, size, 16):
        line = data[off : off + 16]
        hex_cells: list[str] = []
        ascii_cells: list[str] = []

        for i in range(16):
            if i < len(line):
                val = int(line[i])
                is_printable = 0x20 <= val <= 0x7E
                style = ANSI_BOLD if is_printable else ANSI_GRAY
                hex_cells.append(f"{style}{val:02x}{ANSI_RESET}")
                ascii_cells.append(
                    f"{style}{chr(val) if is_printable else '.'}{ANSI_RESET}"
                )
            else:
                hex_cells.append("  ")

        hex_part = " ".join(hex_cells[:8]) + "  " + " ".join(hex_cells[8:])
        ascii_part = "".join(ascii_cells)
        sys.stdout.write(
            f"{ANSI_RED}{off:08x}{ANSI_RESET}  {hex_part} |{ascii_part}|\n"
        )

    sys.stdout.flush()
