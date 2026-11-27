"""Locate the template program passed to known Python compilation APIs."""

import ast

from aegify.models import PythonCallOperand
from aegify.scanner.python_scope import call_argument, python_scopes
from aegify.scanner.python_storage import LocalValues

_COMPILERS = {
    "flask.render_template_string": "source",
    "flask.templating.render_template_string": "source",
    "jinja2.Template": "source",
    "jinja2.environment.Template": "source",
    "django.template.Template": "template_string",
    "django.template.base.Template": "template_string",
}
_ENGINES = {
    "jinja2.Environment": "source",
    "jinja2.environment.Environment": "source",
    "django.template.Engine": "template_code",
    "django.template.engine.Engine": "template_code",
    "django.template.engines": "template_code",
}


def _engine(receiver: ast.expr, local: LocalValues, changed: set[str]) -> str:
    for _ in range(8):
        if isinstance(receiver, ast.Name) and receiver.id in changed:
            return ""
        previous = local.assigned(receiver)
        if previous is None:
            break
        receiver = previous
    if isinstance(receiver, ast.Call):
        factory = local.scope.resolve(receiver.func)
        if factory in _ENGINES and factory != "django.template.engines":
            return factory
    if (
        isinstance(receiver, ast.Subscript)
        and isinstance(receiver.slice, ast.Constant)
        and receiver.slice.value == "django"
        and local.scope.resolve(receiver.value) == "django.template.engines"
    ):
        return "django.template.engines"
    return ""


def template_sources(source: bytes) -> dict[tuple[int, int, int, int], PythonCallOperand]:
    if not any(name in source for name in (b"django", b"jinja2", b"flask")):
        return {}
    if not any(name in source for name in (b"Template", b"from_string", b"render_template_string")):
        return {}
    found = {}
    for scope in python_scopes(source):
        local = None
        changed = {
            node.value.id
            for node in scope.nodes
            if isinstance(node, ast.Attribute)
            and node.attr == "from_string"
            and isinstance(node.ctx, ast.Store | ast.Del)
            and isinstance(node.value, ast.Name)
        }
        for call in scope.nodes:
            if (
                not isinstance(call, ast.Call)
                or call.end_lineno is None
                or call.end_col_offset is None
            ):
                continue
            api = scope.resolve(call.func)
            keyword = _COMPILERS.get(api)
            if isinstance(call.func, ast.Attribute) and call.func.attr == "from_string":
                if local is None:
                    local = LocalValues(scope)
                engine = _engine(call.func.value, local, changed)
                api = engine + ".from_string"
                keyword = _ENGINES.get(engine) if api not in scope.modified else None
            if not keyword:
                continue
            selected = call_argument(call, 0, keyword)
            if selected is None or isinstance(selected[1], ast.Constant):
                continue
            key = call.lineno, call.col_offset, call.end_lineno, call.end_col_offset
            found[key] = PythonCallOperand(api=api, argument_index=selected[0])
    return found
