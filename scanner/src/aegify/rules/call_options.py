"""A strict rule-DSL selector over parsed boolean options."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegify.models import BooleanOption, CallSite


def _property(options: list[BooleanOption] | None, name: str) -> str:
    if options is None:
        return "unknown"
    state = "missing"
    for option in options:
        if option.name is None:
            state = "unknown"
        elif option.name == name:
            state = option.state
    return state


@dataclass(frozen=True)
class BooleanOptionSpec:
    name: str
    location: str
    states: frozenset[str]
    argument: int | str | None = None

    @classmethod
    def parse(cls, data: Any) -> BooleanOptionSpec:
        if not isinstance(data, dict) or set(data) - {"name", "location", "argument", "states"}:
            raise ValueError("boolean_option must contain only name, location, argument and states")
        name = data.get("name")
        location = data.get("location")
        states = data.get("states")
        argument = data.get("argument")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 128
            or any(ord(c) < 32 for c in name)
        ):
            raise ValueError("boolean_option.name must be a bounded property name")
        if location not in {"keyword", "argument"}:
            raise ValueError("boolean_option.location must be keyword or argument")
        if (
            not isinstance(states, list)
            or not states
            or any(
                not isinstance(s, str) or s not in {"true", "false", "missing", "unknown"}
                for s in states
            )
        ):
            raise ValueError(
                "boolean_option.states must list quoted true/false/missing/unknown states"
            )
        if (
            location == "argument"
            and argument != "all"
            and (type(argument) is not int or not 0 <= argument < 128)
        ):
            raise ValueError("boolean_option.argument must be an index below 128 or all")
        if location == "keyword" and "argument" in data:
            raise ValueError("keyword boolean_option does not accept an argument index")
        return cls(name, location, frozenset(states), argument)

    def state(self, call: CallSite) -> str:
        args = call.structured_arguments
        if args is None:
            return "unknown"
        if self.location == "argument":
            if self.argument == "all":
                states = [
                    _property(arg.options, self.name) if arg.kind == "positional" else "unknown"
                    for arg in args
                ]
                return next(
                    (state for state in ("false", "missing", "unknown") if state in states),
                    "true" if states else "missing",
                )
            assert isinstance(self.argument, int)
            if any(arg.kind in {"spread", "unknown"} for arg in args[: self.argument + 1]):
                return "unknown"
            if self.argument >= len(args):
                return "missing"
            return _property(args[self.argument].options, self.name)
        # Python keyword unpacking cannot override an explicit keyword. Multiple
        # possible bindings are unknown, rather than claiming last-write wins.
        state = "missing"
        seen = False
        for arg in args:
            current = (
                arg.state
                if arg.kind == "keyword" and arg.name == self.name
                else _property(arg.options, self.name)
                if arg.kind == "keyword_spread"
                else "unknown"
                if arg.kind == "unknown"
                else "missing"
            )
            if current != "missing":
                if seen:
                    return "unknown"
                seen, state = True, current
        return state
