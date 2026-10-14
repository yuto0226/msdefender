"""Immutable Boolean expressions with a human-readable YARA-like presentation.

Selectors are display hints for the explicit AtLeast atoms. Evaluation always
uses those atoms; a caller supplying a wildcard must supply its complete set.
This module has no scanner, score, ANSI, or verdict semantics.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Const:
    value: bool


@dataclass(frozen=True, slots=True)
class Atom:
    identifier: str


@dataclass(frozen=True, slots=True)
class AtLeast:
    count: int
    atoms: tuple[Atom, ...]
    selector: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "atoms", tuple(dict.fromkeys(self.atoms)))
        if self.count < 0:
            raise ValueError("negative cardinality")
        if (
            self.selector is not None
            and self.selector != "them"
            and (
                not self.selector.endswith("*")
                or any(
                    not atom.identifier.startswith(self.selector[:-1])
                    for atom in self.atoms
                )
            )
        ):
            raise ValueError("selector does not contain its atoms")


@dataclass(frozen=True, slots=True)
class And:
    terms: tuple[Expr, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "terms", tuple(self.terms))


@dataclass(frozen=True, slots=True)
class Or:
    terms: tuple[Expr, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "terms", tuple(self.terms))


@dataclass(frozen=True, slots=True)
class Not:
    term: Expr


type Expr = Const | Atom | AtLeast | And | Or | Not


def at_least(count: int, atoms: tuple[Atom, ...], selector: str | None = None) -> Expr:
    node = AtLeast(count, atoms, selector)
    if count == 0:
        return Const(True)
    if count > len(node.atoms):
        return Const(False)
    return node


def conjunction(*terms: Expr) -> Expr:
    return _combine(And, terms)


def disjunction(*terms: Expr) -> Expr:
    return _combine(Or, terms)


def _combine(kind: type[And | Or], terms: tuple[Expr, ...]) -> Expr:
    identity = kind is And
    flattened: list[Expr] = []
    for term in terms:
        if isinstance(term, Const):
            if term.value != identity:
                return term
        elif isinstance(term, kind):
            flattened.extend(term.terms)
        else:
            flattened.append(term)
    # Revisit flattened nodes so constants and duplicates normalize uniformly.
    if any(isinstance(term, (kind, Const)) for term in flattened):
        return _combine(kind, tuple(flattened))
    unique = tuple(dict.fromkeys(flattened))
    if not unique:
        return Const(identity)
    return unique[0] if len(unique) == 1 else kind(unique)


def negate(term: Expr) -> Expr:
    if isinstance(term, Const):
        return Const(not term.value)
    return term.term if isinstance(term, Not) else Not(term)


def evaluate(expr: Expr, matched_ids: Collection[str]) -> bool:
    if isinstance(expr, Const):
        return expr.value
    if isinstance(expr, Atom):
        return expr.identifier in matched_ids
    if isinstance(expr, AtLeast):
        return sum(atom.identifier in matched_ids for atom in expr.atoms) >= expr.count
    if isinstance(expr, And):
        return all(evaluate(term, matched_ids) for term in expr.terms)
    if isinstance(expr, Or):
        return any(evaluate(term, matched_ids) for term in expr.terms)
    if isinstance(expr, Not):
        return not evaluate(expr.term, matched_ids)
    raise TypeError(f"unsupported expression {type(expr).__name__}")


def _precedence(expr: Expr) -> int:
    return (
        1
        if isinstance(expr, Or)
        else 2
        if isinstance(expr, And)
        else 3
        if isinstance(expr, Not)
        else 4
    )


def _cardinality_parts(expr: AtLeast) -> tuple[str, str]:
    quantifier = (
        "all"
        if expr.count == len(expr.atoms)
        else "any"
        if expr.count == 1
        else str(expr.count)
    )
    selector = expr.selector or f"({', '.join(atom.identifier for atom in expr.atoms)})"
    return quantifier, selector


def render_yara_like(expr: Expr) -> str:
    """Render not > and > or, adding only parentheses that change precedence."""
    if isinstance(expr, Const):
        return "true" if expr.value else "false"
    if isinstance(expr, Atom):
        return expr.identifier
    if isinstance(expr, AtLeast):
        quantifier, selector = _cardinality_parts(expr)
        return f"{quantifier} of {selector}"
    if isinstance(expr, Not):
        text = render_yara_like(expr.term)
        return f"not ({text})" if _precedence(expr.term) < 3 else f"not {text}"
    if isinstance(expr, (And, Or)):
        if not expr.terms:
            return "true" if isinstance(expr, And) else "false"
        separator = " and " if isinstance(expr, And) else " or "
        return separator.join(
            f"({render_yara_like(term)})"
            if _precedence(term) < _precedence(expr)
            else render_yara_like(term)
            for term in expr.terms
        )
    raise TypeError(f"unsupported expression {type(expr).__name__}")


def rendered_length(expr: Expr) -> int:
    """Measure presentation size without materializing a Boolean expression string."""
    if isinstance(expr, Const):
        return 4 if expr.value else 5
    if isinstance(expr, Atom):
        return len(expr.identifier)
    if isinstance(expr, AtLeast):
        quantifier, selector = _cardinality_parts(expr)
        return len(quantifier) + 4 + len(selector)
    if isinstance(expr, Not):
        return 4 + rendered_length(expr.term) + (2 if _precedence(expr.term) < 3 else 0)
    if isinstance(expr, (And, Or)):
        if not expr.terms:
            return 4 if isinstance(expr, And) else 5
        separator_length = 5 if isinstance(expr, And) else 4
        return sum(
            rendered_length(term) + (2 if _precedence(term) < _precedence(expr) else 0)
            for term in expr.terms
        ) + separator_length * (len(expr.terms) - 1)
    raise TypeError(f"unsupported expression {type(expr).__name__}")
