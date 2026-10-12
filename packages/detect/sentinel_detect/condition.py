"""Sigma ``condition`` expression grammar (Stage-5 §3 lint grammar subset).

Grammar implemented (case-insensitive keywords):

    condition   := or_expr | '[' or_expr (',' or_expr)* ']'      # list = OR
    or_expr     := and_expr ( ('or' | '||') and_expr )*
    and_expr    := not_expr ( ('and' | '&&') not_expr )*
    not_expr    := ('not' | '!') not_expr | primary
    primary     := '(' or_expr ')' | of_expr | identifier
    of_expr     := ('all' | INTEGER) 'of' ( 'them' | pattern )
    pattern     := identifier, optionally containing '*' wildcards

AST nodes are plain tuples so the compiler and the native evaluator can share
them without an import cycle:

    ("or", left, right)          ("and", left, right)
    ("not", child)               ("ident", name)
    ("of", count, pattern)       count is int, ``'all'``, or ``'*'`` (all-of)
"""
from __future__ import annotations

import re
from typing import Any, Iterable

__all__ = [
    "ConditionError",
    "parse_condition",
    "identifiers_in",
    "wildcard_pattern",
]


class ConditionError(ValueError):
    """Raised when a ``condition`` string is outside the supported grammar."""


_TOKEN = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<lbracket>\[)
    | (?P<rbracket>\])
    | (?P<comma>,)
    | (?P<and>\band\b|&&)
    | (?P<or>\bor\b|\|\|)
    | (?P<not>\bnot\b|!)
    | (?P<int>\d+)
    | (?P<word>[A-Za-z_][A-Za-z0-9_.]*(?:\*[A-Za-z0-9_.]*)?)
    | (?P<star>\*)
    | (?P<other>.)
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if m is None:  # pragma: no cover - regex has a catch-all
            raise ConditionError(f"cannot tokenize condition at offset {pos}")
        pos = m.end()
        kind = m.lastgroup or ""
        if kind == "ws":
            continue
        value = m.group()
        tokens.append((kind, value))
    return tokens


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.i = 0

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        self.i += 1
        return tok

    def accept(self, kind: str, value: str | None = None) -> tuple[str, str] | None:
        tok = self.peek()
        if tok is None:
            return None
        if tok[0] != kind:
            return None
        if value is not None and tok[1].lower() != value.lower():
            return None
        return self.take()

    def parse(self) -> Any:
        node = self.parse_or()
        if self.peek() is not None:
            raise ConditionError(f"trailing token {self.peek()!r}")
        return node

    def parse_or(self) -> Any:
        node = self.parse_and()
        while self.accept("or") is not None:
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self) -> Any:
        node = self.parse_not()
        while self.accept("and") is not None:
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self) -> Any:
        if self.accept("not") is not None:
            return ("not", self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> Any:
        tok = self.peek()
        if tok is None:
            raise ConditionError("unexpected end of condition")
        if tok[0] == "lparen":
            self.take()
            node = self.parse_or()
            if self.accept("rparen") is None:
                raise ConditionError("missing ')'")
            return node
        if tok[0] == "int":
            self.take()
            self._expect_of()
            return ("of", int(tok[1]), self._pattern())
        if tok[0] == "word" and tok[1].lower() == "all":
            self.take()
            self._expect_of()
            return ("of", "all", self._pattern())
        if tok[0] in ("word", "star"):
            self.take()
            return ("ident", tok[1])
        raise ConditionError(f"unexpected token {tok!r}")

    def _expect_of(self) -> None:
        nxt = self.peek()
        if nxt is None or nxt[1].lower() != "of":
            raise ConditionError("expected 'of'")
        self.take()

    def _pattern(self) -> str:
        tok = self.peek()
        if tok is None or tok[0] not in ("word", "star"):
            raise ConditionError("expected an identifier or pattern after 'of'")
        self.take()
        return tok[1]


def parse_condition(condition: Any) -> Any:
    """Parse a Sigma ``condition`` into an AST node.

    A list condition is OR across its items (sigma-spec: condition-as-list).
    """
    if isinstance(condition, (list, tuple)):
        if not condition:
            raise ConditionError("empty condition list")
        node = parse_condition(condition[0])
        for item in condition[1:]:
            node = ("or", node, parse_condition(item))
        return node
    if not isinstance(condition, str) or not condition.strip():
        raise ConditionError("condition must be a non-empty string")
    return _Parser(_tokenize(condition)).parse()


def identifiers_in(node: Any) -> set[str]:
    """Every ``("ident", name)`` referenced anywhere in the AST."""
    out: set[str] = set()

    def walk(n: Any) -> None:
        if not isinstance(n, tuple) or not n:
            return
        if n[0] == "ident":
            out.add(n[1])
        elif n[0] in ("and", "or"):
            walk(n[1])
            walk(n[2])
        elif n[0] == "not":
            walk(n[1])

    walk(node)
    return out


def wildcard_pattern(pattern: str) -> re.Pattern[str]:
    """``selection_*`` -> anchored regex over detection-key names."""
    parts = [re.escape(p) for p in pattern.split("*")]
    return re.compile("^" + ".*".join(parts) + "$", re.IGNORECASE)


def matching_identifiers(node: Any, keys: Iterable[str]) -> set[str]:
    """Resolve ``("of", n, pattern)`` wildcards against ``keys``.

    Returns the union of every explicitly named identifier plus every key
    matching a pattern used by an ``of`` expression.
    """
    keys = list(keys)
    out: set[str] = identifiers_in(node)
    patterns: list[str] = []

    def walk(n: Any) -> None:
        if not isinstance(n, tuple) or not n:
            return
        if n[0] == "of":
            patterns.append(n[2])
        elif n[0] in ("and", "or"):
            walk(n[1])
            walk(n[2])
        elif n[0] == "not":
            walk(n[1])

    walk(node)
    for pat in patterns:
        if pat.lower() == "them":
            out.update(keys)
        else:
            rx = wildcard_pattern(pat)
            out.update(k for k in keys if rx.match(k))
    return out
