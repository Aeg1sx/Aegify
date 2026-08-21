"""JVM source-descriptor normalization and overload compatibility."""

from __future__ import annotations

from codeguard.models import CallSite, FunctionDef


def normalize_jvm_type(value: str) -> str:
    """Normalize Java/Kotlin source spellings for conservative matching."""

    candidate = FunctionDef._normalize_type(value)
    candidate = candidate.removesuffix("...").removesuffix("[]")
    candidate = candidate.removesuffix("?")
    candidate = candidate.rsplit(".", 1)[-1]
    aliases = {
        "Boolean": "boolean",
        "Byte": "byte",
        "Character": "char",
        "Char": "char",
        "Double": "double",
        "Float": "float",
        "Int": "int",
        "Integer": "int",
        "Long": "long",
        "Short": "short",
        "String": "string",
        "Nothing": "null",
    }
    return aliases.get(candidate, candidate)


def type_compatibility(actual: str, expected: str) -> int:
    """Return a relative score, or -1 for a definitely incompatible type."""

    actual_type = normalize_jvm_type(actual)
    expected_type = normalize_jvm_type(expected)
    if not actual_type or not expected_type or expected_type == "?":
        return 0
    if actual_type == expected_type:
        return 4
    if actual_type == "null":
        primitives = {
            "boolean",
            "byte",
            "char",
            "double",
            "float",
            "int",
            "long",
            "short",
        }
        return -1 if expected_type in primitives else 1
    numeric_widening = {
        "byte": {"short", "int", "long", "float", "double"},
        "short": {"int", "long", "float", "double"},
        "char": {"int", "long", "float", "double"},
        "int": {"long", "float", "double"},
        "long": {"float", "double"},
        "float": {"double"},
    }
    if expected_type in numeric_widening.get(actual_type, set()):
        return 1
    return -1


def jvm_overload_score(call: CallSite, function: FunctionDef) -> int | None:
    """Score one callable using arity, defaults, varargs, and known types."""

    argument_count = len(call.arguments)
    parameter_count = len(function.parameters)
    defaults = list(function.parameter_defaults[:parameter_count])
    defaults.extend(False for _ in range(parameter_count - len(defaults)))
    required = sum(
        1
        for index, has_default in enumerate(defaults)
        if not has_default and not (function.variadic and index == parameter_count - 1)
    )
    if argument_count < required:
        return None
    if not function.variadic and argument_count > parameter_count:
        return None

    score = 4 if argument_count == parameter_count else 2
    parameter_types = list(function.parameter_types[:parameter_count])
    parameter_types.extend("" for _ in range(parameter_count - len(parameter_types)))
    for index, actual in enumerate(call.argument_types):
        if not actual:
            continue
        parameter_index = min(index, parameter_count - 1)
        if parameter_index < 0:
            return None
        compatibility = type_compatibility(actual, parameter_types[parameter_index])
        if compatibility < 0:
            return None
        score += compatibility
    return score
