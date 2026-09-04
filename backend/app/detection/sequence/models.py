"""Safe, constrained predicate matching over canonical events.

Predicates are declarative data — field/operator comparisons — never executable
Python. This lets sequence definitions be configured safely while preserving
ordering guarantees.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PredicateOperator(str, Enum):
    """Supported comparison operators for a predicate field."""

    EQ = "eq"
    IN = "in"


@dataclass(frozen=True)
class Predicate:
    """A single declarative event predicate.

    Matches a canonical event when, for each ``(field, operator, value)``, the
    event's attribute satisfies the operator. Only the attributes that exist on
    a canonical event may be referenced.

    Examples:
        Predicate(event_type="system_call")
        Predicate(syscall="open")
        Predicate(process_name="bash")
        Predicate(protocol="TCP")
        Predicate(destination_port=22)
    """

    field: str
    operator: PredicateOperator = PredicateOperator.EQ
    value: Any = None

    def matches(self, event: Any) -> bool:
        actual = getattr(event, self.field, None)
        if actual is None:
            # Match against attributes as a fallback for extensible data.
            attrs = getattr(event, "attributes", {}) or {}
            if self.field in attrs:
                actual = attrs[self.field]
            else:
                return False
        if self.operator == PredicateOperator.EQ:
            return _coerce_eq(actual, self.value)
        if self.operator == PredicateOperator.IN:
            if isinstance(self.value, (list, tuple, set, frozenset)):
                return any(_coerce_eq(actual, v) for v in self.value)
            return False
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator.value,
            "value": self.value,
        }


def _coerce_eq(actual: Any, expected: Any) -> bool:
    if isinstance(actual, Enum):
        actual = actual.value
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.casefold() == expected.casefold()
    return actual == expected


def predicate(
    field: str,
    value: Any,
    operator: str = "eq",
) -> Predicate:
    """Convenience constructor for a single-field predicate."""
    return Predicate(field=field, operator=PredicateOperator(operator), value=value)


@dataclass(frozen=True)
class SequenceDefinition:
    """A named, ordered predicate sequence.

    ``predicates`` is an ordered list ``[A, B, C]`` meaning "A, then B, then C".
    Ordering is mandatory. An optional ``time_window_seconds`` may be supplied;
    it is only enforced when timestamps are available.
    """

    id: str
    name: str
    predicates: tuple[Predicate, ...] = field(default_factory=tuple)
    time_window_seconds: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "predicates": [p.to_dict() for p in self.predicates],
            "time_window_seconds": self.time_window_seconds,
        }
