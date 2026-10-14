"""Immutable Boolean expressions with a human-readable YARA-like presentation.

Selectors are display hints for the explicit AtLeast atoms. Evaluation always
uses those atoms; a caller supplying a wildcard must supply its complete set.
This module has no scanner, score, ANSI, or verdict semantics.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from itertools import combinations


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


def _node_count(expr: Expr) -> int:
    if isinstance(expr, AtLeast):
        return 1 + len(expr.atoms)
    if isinstance(expr, (And, Or)):
        return 1 + sum(_node_count(term) for term in expr.terms)
    return 1 + _node_count(expr.term) if isinstance(expr, Not) else 1


def _expression_cost(expr: Expr) -> tuple[int, int, str]:
    return rendered_length(expr), _node_count(expr), render_yara_like(expr)


def _atom_identifiers(expr: Expr) -> frozenset[str]:
    if isinstance(expr, Atom):
        return frozenset((expr.identifier,))
    if isinstance(expr, AtLeast):
        return frozenset(atom.identifier for atom in expr.atoms)
    if isinstance(expr, (And, Or)):
        return frozenset().union(*(_atom_identifiers(term) for term in expr.terms))
    return _atom_identifiers(expr.term) if isinstance(expr, Not) else frozenset()


def select_equivalent(
    source: Expr, candidates: Collection[Expr], identifiers: tuple[str, ...]
) -> Expr:
    """Choose the cheapest fully equivalent candidate over a bounded atom universe."""
    universe = frozenset(identifiers)
    if (
        len(identifiers) > 8
        or len(candidates) > 8
        or not _atom_identifiers(source) <= universe
    ):
        return source
    assignments = tuple(
        frozenset(
            identifier
            for index, identifier in enumerate(identifiers)
            if mask & (1 << index)
        )
        for mask in range(1 << len(identifiers))
    )
    expected = tuple(evaluate(source, matched) for matched in assignments)
    valid = [source]
    for candidate in candidates:
        if not _atom_identifiers(candidate) <= universe:
            continue
        if all(
            evaluate(candidate, matched) == value
            for matched, value in zip(assignments, expected)
        ):
            valid.append(candidate)
    return min(valid, key=_expression_cost)


def minimize_dnf(expr: Expr) -> Expr:
    """Factor common conjuncts in at most four monotone clauses/eight variables.

    Search is deterministic and bounded to 64 states/128 candidates. The only
    rewrite is distributivity plus the existing local smart constructors. Every
    candidate is checked against its source on all Boolean assignments.
    """
    roots = expr.terms if isinstance(expr, Or) else (expr,)
    if not 2 <= len(roots) <= 4:
        return expr
    clauses = tuple(term.terms if isinstance(term, And) else (term,) for term in roots)
    if any(
        not isinstance(leaf, (Atom, AtLeast, Const))
        for clause in clauses
        for leaf in clause
    ):
        return expr
    identifiers = sorted(
        {
            atom.identifier
            for clause in clauses
            for leaf in clause
            for atom in (
                (leaf,)
                if isinstance(leaf, Atom)
                else leaf.atoms
                if isinstance(leaf, AtLeast)
                else ()
            )
        }
    )
    if len(identifiers) > 8:
        return expr
    assignments = tuple(
        frozenset(
            identifier
            for index, identifier in enumerate(identifiers)
            if mask & (1 << index)
        )
        for mask in range(1 << len(identifiers))
    )
    memo: dict[tuple[tuple[Expr, ...], ...], Expr] = {}
    candidates = 0

    def solve(parts: tuple[tuple[Expr, ...], ...]) -> Expr:
        nonlocal candidates
        baseline = disjunction(*(conjunction(*clause) for clause in parts))
        if parts in memo:
            return memo[parts]
        if len(memo) >= 64 or candidates >= 128:
            return baseline
        memo[parts] = baseline
        expected = tuple(evaluate(baseline, matched) for matched in assignments)
        best = baseline
        for size in range(2, len(parts) + 1):
            for selected in combinations(range(len(parts)), size):
                common = tuple(
                    leaf
                    for leaf in parts[selected[0]]
                    if all(leaf in parts[index] for index in selected[1:])
                )
                if not common:
                    continue
                candidates += 1
                if candidates > 128:
                    memo[parts] = best
                    return best
                remainder = tuple(
                    tuple(leaf for leaf in parts[index] if leaf not in common)
                    for index in selected
                )
                others = tuple(
                    clause
                    for index, clause in enumerate(parts)
                    if index not in selected
                )
                factored = conjunction(*common, solve(remainder))
                candidate = disjunction(factored, solve(others)) if others else factored
                if all(
                    evaluate(candidate, matched) == value
                    for matched, value in zip(assignments, expected)
                ) and _expression_cost(candidate) < _expression_cost(best):
                    best = candidate
        memo[parts] = best
        return best

    result = solve(clauses)
    return (
        result
        if all(
            evaluate(result, matched) == evaluate(expr, matched)
            for matched in assignments
        )
        else expr
    )


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
