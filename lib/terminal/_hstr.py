from __future__ import annotations

from lib.debug import (
    ANSI_BWHITE,
    ANSI_GRAY,
    ANSI_RED,
    ANSI_RESET,
    ANSI_YELLOW,
)
from lib.vdm.bm_yara import BmYaraFidelity, BmYaraRender
from lib.vdm.core import Field


def _highlight_strings(value: str) -> str:
    parts: list[str] = []
    cursor = 0
    while cursor < len(value):
        start = value.find('"', cursor)
        if start < 0:
            parts.append(value[cursor:])
            break
        parts.append(value[cursor:start])
        end = start + 1
        while end < len(value):
            if value[end] == "\\":
                end += 2
            elif value[end] == '"':
                parts.append(f"{ANSI_YELLOW}{value[start : end + 1]}{ANSI_RESET}")
                cursor = end + 1
                break
            else:
                end += 1
        else:
            parts.append(value[start:])
            break
    return "".join(parts)


def _tokens(value: str) -> list[str]:
    tokens: list[str] = []
    cursor = 0
    while cursor < len(value):
        if value[cursor].isspace():
            cursor += 1
            continue
        start = cursor
        char = value[cursor]
        if char == '"':
            cursor += 1
            while cursor < len(value):
                if value[cursor] == "\\":
                    cursor += 2
                elif value[cursor] == '"':
                    cursor += 1
                    break
                else:
                    cursor += 1
        elif char in "([":
            opening, closing = ("(", ")") if char == "(" else ("[", "]")
            depth = 0
            while cursor < len(value):
                if value[cursor] == opening:
                    depth += 1
                elif value[cursor] == closing:
                    depth -= 1
                    if depth == 0:
                        cursor += 1
                        break
                cursor += 1
        elif char in "{}":
            cursor += 1
        else:
            while cursor < len(value) and not value[cursor].isspace():
                cursor += 1
        tokens.append(value[start:cursor])
    return tokens


def _wrap_tokens(
    tokens: list[str],
    *,
    first: str,
    indent: str,
    width: int,
    continuation: str | None = None,
) -> list[str]:
    lines: list[str] = []
    current = indent + first
    continuation = continuation or indent + "    "
    has_token = bool(first)
    for token in tokens:
        candidate = current + (" " if has_token else "") + token
        if has_token and len(candidate) > width:
            lines.append(current)
            current = continuation + token
            has_token = True
        elif not has_token and len(candidate) > width and current.strip():
            lines.append(current.rstrip())
            current = continuation + token
            has_token = True
        else:
            current = candidate
            has_token = True
    if current.strip() or not lines:
        lines.append(current.rstrip())
    return lines


def _wrap_comment_tokens(
    tokens: list[str], *, prefix: str, indent: str, width: int
) -> list[str]:
    if not tokens:
        return [indent + prefix.rstrip()]
    lines: list[str] = []
    current = indent + prefix
    has_token = False
    for token in tokens:
        candidate = current + (" " if has_token else "") + token
        if has_token and len(candidate) > width:
            lines.append(current)
            current = indent + prefix + token
        else:
            current = candidate
        has_token = True
    lines.append(current)
    return lines


def _comment_lines(
    *, preview: str | None, conditional: tuple[str, ...], indent: str, width: int
) -> list[str]:
    lines: list[str] = []
    if preview is not None:
        preview_tokens = _tokens(preview)
        inline = f"// preview: {preview}"
        if len(indent + inline) <= width:
            lines.append(indent + inline)
        else:
            lines.append(indent + "// preview:")
            lines.extend(
                _wrap_comment_tokens(
                    preview_tokens, prefix="//   ", indent=indent, width=width
                )
            )
    if conditional:
        inline = "// conditional: " + ", ".join(conditional)
        if len(indent + inline) <= width:
            lines.append(indent + inline)
        else:
            lines.append(indent + "// conditional:")
            requirements: list[str] = []
            for index, requirement in enumerate(conditional):
                words = requirement.split()
                if words and index + 1 < len(conditional):
                    words[-1] += ","
                requirements.extend(words or (requirement,))
            lines.extend(
                _wrap_comment_tokens(
                    requirements, prefix="//   ", indent=indent, width=width
                )
            )
    return lines


def _declaration(
    *,
    identifier: str | None,
    rhs: str | None,
    indent: str,
    width: int,
    preview: str | None = None,
    conditional: tuple[str, ...] = (),
    unsupported: tuple[str, ...] | None = None,
) -> list[str]:
    if unsupported is not None:
        codes = unsupported or ("unsupported",)
        lines: list[str] = []
        current = indent + "yara: "
        has_code = False
        continuation = indent + "      "
        for index, code in enumerate(codes):
            token = code + ("," if index + 1 < len(codes) else "")
            candidate = current + (" " if has_code else "") + token
            if has_code and len(candidate) > width:
                lines.append(current.rstrip())
                current = continuation + token
            else:
                current = candidate
            has_code = True
        lines.append(current.rstrip())
        if preview is not None:
            comment = "// preview: " + preview
            if len(lines) == 1 and len(lines[0] + "  " + comment) <= width:
                return [_highlight_strings(lines[0] + "  " + comment)]
            lines.extend(
                _comment_lines(
                    preview=preview, conditional=(), indent=indent, width=width
                )
            )
        return [_highlight_strings(line) for line in lines]

    prefix = f"{identifier} = "
    body = rhs or ""
    base = prefix + body
    clauses: list[str] = []
    if preview is not None:
        clauses.append("preview: " + preview)
    if conditional:
        clauses.append("conditional: " + ", ".join(conditional))
    full = indent + base
    if clauses:
        full += "  // " + "; ".join(clauses)
    if len(full) <= width:
        return [_highlight_strings(full)]

    if body.startswith("{") and body.endswith("}"):
        tokens = _tokens(body)
        if len(indent + prefix + body) > width:
            inner = [token for token in tokens if token not in ("{", "}")]
            lines = [indent + prefix.rstrip() + " {"]
            if inner:
                lines.extend(
                    _wrap_tokens(
                        inner,
                        first="",
                        indent=indent + "    ",
                        width=width,
                        continuation=indent + "    ",
                    )
                )
            lines.append(indent + "}")
        else:
            lines = [indent + base]
    else:
        lines = _wrap_tokens(
            _tokens(body), first=prefix.rstrip(), indent=indent, width=width
        )
    lines.extend(
        _comment_lines(
            preview=preview, conditional=conditional, indent=indent, width=width
        )
    )
    return [_highlight_strings(line) for line in lines]


def render_fields(
    fields: tuple[Field, ...] | list[Field],
    indent: str,
    *,
    width: int,
    bm_yara: BmYaraRender | None = None,
    printable_preview: str | None = None,
    yara_unsupported: tuple[str, ...] = (),
) -> list[str]:
    remaining = list(fields)
    lines: list[str] = []
    if not remaining:
        return lines
    values = dict(remaining)
    metadata = ("tag", "flags", "matching")
    if all(label in values for label in metadata):
        icon = (
            f"{ANSI_YELLOW}[!]{ANSI_RESET} "
            if "UNKNOWN_BITS(" in values["flags"]
            else ""
        )
        detail = ", ".join(f"{label}={values[label]}" for label in metadata)
        lines.append(f"{indent}{icon}{ANSI_GRAY}{detail}{ANSI_RESET}")
        remaining = [
            (label, value) for label, value in remaining if label not in metadata
        ]
    identifier = values.get("identifier")
    display = values.get("display")
    if identifier is not None and display is not None:
        if yara_unsupported:
            lines.extend(
                _declaration(
                    identifier=None,
                    rhs=None,
                    indent=indent,
                    width=width,
                    preview=printable_preview,
                    unsupported=yara_unsupported,
                )
            )
        elif bm_yara is None:
            lines.extend(
                _declaration(
                    identifier=identifier,
                    rhs=display,
                    indent=indent,
                    width=width,
                    preview=printable_preview,
                )
            )
        elif bm_yara.body is None:
            lines.extend(
                _declaration(
                    identifier=None,
                    rhs=None,
                    indent=indent,
                    width=width,
                    preview=bm_yara.printable_preview,
                    unsupported=tuple(issue.code for issue in bm_yara.diagnostics),
                )
            )
        else:
            conditional = (
                bm_yara.requirements
                if bm_yara.fidelity == BmYaraFidelity.CONDITIONAL
                else ()
            )
            lines.extend(
                _declaration(
                    identifier=identifier,
                    rhs=bm_yara.body,
                    indent=indent,
                    width=width,
                    preview=bm_yara.printable_preview,
                    conditional=conditional,
                )
            )
        remaining = [
            (label, value)
            for label, value in remaining
            if label not in ("identifier", "display")
        ]
    if not remaining:
        return lines
    label_width = max(len(label) for label, _ in remaining)
    for label, value in remaining:
        if label == "display":
            value = _highlight_strings(value)
        icon = ""
        if label.lower() == "error":
            icon = f"{ANSI_RED}[!]{ANSI_RESET} "
        elif (
            label in ("warning", "tail_word0")
            or (label == "flags" and "UNKNOWN_BITS(" in value)
            or (label == "trailing_raw" and not value.startswith("0 B"))
        ):
            icon = f"{ANSI_YELLOW}[!]{ANSI_RESET} "
        lines.append(
            f"{indent}{icon}{ANSI_BWHITE}{label:<{label_width}}{ANSI_RESET} : {value}"
        )
    return lines
