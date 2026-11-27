"""Bind HTTP redirect destinations and narrowly scoped URL checks in Python source."""

from __future__ import annotations

import ast
import re

from aegify.models import CallSite, FileAST, PythonRedirect
from aegify.scanner.python_scope import (
    PythonModules,
    call_argument,
    dominating_facts,
    python_scopes,
)
from aegify.scanner.python_text import TextValues

_DESTINATIONS = {
    "flask.redirect": "location",
    "flask.helpers.redirect": "location",
    "flask.current_app.redirect": "location",
    "werkzeug.utils.redirect": "location",
    "django.shortcuts.redirect": "to",
    "django.http.HttpResponseRedirect": "redirect_to",
    "django.http.HttpResponsePermanentRedirect": "redirect_to",
    "django.http.response.HttpResponseRedirect": "redirect_to",
    "django.http.response.HttpResponsePermanentRedirect": "redirect_to",
    "starlette.responses.RedirectResponse": "url",
    "fastapi.responses.RedirectResponse": "url",
}
_PARSERS = {"urllib.parse.urlparse", "urllib.parse.urlsplit"}
_ALLOWED_URL = "django.utils.http.url_has_allowed_host_and_scheme"
_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_AUTHORITY = re.compile(rf"{_LABEL}(?:\.{_LABEL})*(?::[0-9]{{1,5}})?")


def _strings(value: ast.expr, local: TextValues, *, scalar: bool | None) -> list[str] | None:
    if isinstance(value, ast.Name):
        bound = local.assigned(value)
        if not isinstance(bound, ast.Constant | ast.Tuple):
            return None
        value = bound
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return [value.value] if scalar is not False else None
    if (
        scalar is True
        or not isinstance(value, ast.List | ast.Set | ast.Tuple)
        or len(value.elts) > 128
    ):
        return None
    strings = [
        item.value
        for item in value.elts
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    ]
    return strings if len(strings) == len(value.elts) else None


def _hosts(values: list[str]) -> bool:
    return all(
        0 < len(value) <= 255
        and _AUTHORITY.fullmatch(value)
        and (":" not in value or 0 < int(value.rpartition(":")[2]) <= 65535)
        for value in values
    )


class _Destination:
    def __init__(self, local: TextValues, value: ast.Name, use: ast.Call) -> None:
        self.local = local
        self.name = value.id
        self.use = use

    def unchanged(self, origin: ast.expr) -> bool:
        return self.local.unchanged(self.name, origin, self.use)

    def django_check(self, test: ast.Call) -> bool:
        if self.local.scope.resolve(test.func) != _ALLOWED_URL or len(test.args) + len(
            test.keywords
        ) not in {2, 3}:
            return False
        url, hosts = call_argument(test, 0, "url"), call_argument(test, 1, "allowed_hosts")
        if not url or not hosts or not self.unchanged(url[1]):
            return False
        if len(test.args) + len(test.keywords) == 3:
            strict = call_argument(test, 2, "require_https")
            if (
                not strict
                or not isinstance(strict[1], ast.Constant)
                or type(strict[1].value) is not bool
            ):
                return False
        if isinstance(hosts[1], ast.Constant) and hosts[1].value is None:
            return True
        values = _strings(hosts[1], self.local, scalar=None)
        return values is not None and _hosts(values)

    def comparison(self, test: ast.Compare, truth: bool) -> str:
        if len(test.ops) != 1 or not isinstance(test.left, ast.Attribute):
            return ""
        field = test.left
        if field.attr not in {"scheme", "netloc"}:
            return ""
        parser = self.local.assigned(field.value) or field.value
        if (
            not isinstance(parser, ast.Call)
            or self.local.scope.resolve(parser.func) not in _PARSERS
        ):
            return ""
        value = call_argument(parser, 0, "url")
        if (
            not value
            or len(parser.args) + len(parser.keywords) != 1
            or not self.unchanged(value[1])
        ):
            return ""
        op = test.ops[0]
        equal = isinstance(op, ast.Eq if truth else ast.NotEq)
        member = isinstance(op, ast.In if truth else ast.NotIn)
        if not (equal or member):
            return ""
        operand = test.comparators[0]
        values = _strings(operand, self.local, scalar=equal)
        if not values:
            return ""
        if field.attr == "scheme":
            return "scheme" if set(values) <= {"https", "http"} else ""
        return "netloc" if _hosts(values) else ""


def _validator(local: TextValues, call: ast.Call, value: ast.expr) -> str:
    if not isinstance(value, ast.Name) or local.in_loop(call) or not local.string_value(value):
        return ""
    dest = _Destination(local, value, call)
    fields = set()
    for test, truth in dominating_facts(local.scope, call):
        if isinstance(test, ast.Call) and truth and dest.django_check(test):
            return _ALLOWED_URL
        if isinstance(test, ast.Compare):
            fields.add(dest.comparison(test, truth))
            if {"scheme", "netloc"} <= fields:
                return "urllib.parse"
    return ""


def redirect_calls(source: bytes) -> dict[tuple[int, int, int, int], PythonRedirect]:
    if b"redirect" not in source.lower():
        return {}
    found = {}
    for scope in python_scopes(source):
        local = None
        for call in scope.nodes:
            if (
                not isinstance(call, ast.Call)
                or (api := scope.resolve(call.func)) not in _DESTINATIONS
            ):
                continue
            selected = call_argument(call, 0, _DESTINATIONS[api])
            if not selected or call.end_lineno is None or call.end_col_offset is None:
                continue
            if local is None:
                local = TextValues(scope)
            found[call.lineno, call.col_offset, call.end_lineno, call.end_col_offset] = (
                PythonRedirect(
                    api=api,
                    argument_index=selected[0],
                    validator=_validator(local, call, selected[1]),
                )
            )
    return found


def redirect_operand(
    call: CallSite, file: FileAST, modules: PythonModules
) -> tuple[str, int] | None:
    fact = call.python_redirect
    if not fact:
        if file.python_redirect_resolved:
            return None
        name = f"{call.receiver}.{call.callee}" if call.receiver else call.callee
        return (name, 0) if name in _DESTINATIONS or name == "redirect" else None
    if not modules.external(file, fact.api):
        return None
    if fact.validator and all(
        modules.external(file, api)
        for api in (fact.validator, "flask", "base64", "urllib", "builtins")
    ):
        return None
    return fact.api, fact.argument_index
