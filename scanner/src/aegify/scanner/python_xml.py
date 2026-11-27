"""Select XPath programs and recognize SAX external-entity settings in Python source."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from typing import Literal

from aegify.models import XMLInvocation
from aegify.scanner.python_literals import LiteralInputs
from aegify.scanner.python_scope import call_argument, python_scopes
from aegify.scanner.python_text import TextValues

type _Mode = Literal["entities_enabled", "entities_disabled", "parser_unknown"]
type _Position = tuple[int, int, int, int]
_XPATH_ARGUMENTS = {
    "lxml.etree.XPath": (0, "path"),
    "lxml.etree.ETXPath": (0, "path"),
    "elementpath.select": (1, "path"),
    "elementpath.iter_select": (1, "path"),
    "elementpath.Selector": (0, "path"),
}
_LXML_TREES = {
    "lxml.etree.parse",
    "lxml.etree.fromstring",
    "lxml.etree.fromstringlist",
    "lxml.etree.XML",
    "lxml.etree.HTML",
    "lxml.etree.Element",
    "lxml.etree.ElementTree",
}
_DOM_INPUTS = {
    "xml.dom.minidom.parseString": "string",
    "xml.dom.minidom.parse": "file",
    "xml.dom.pulldom.parseString": "string",
    "xml.dom.pulldom.parse": "stream_or_string",
}
_ENTITY_FEATURE = "http://xml.org/sax/features/external-general-entities"
_STEP = r"[A-Za-z_][\w.:-]*"
_QUOTED_ATTRIBUTE = re.compile(rf"(?:\.?//?)?{_STEP}(?:/{_STEP})*\[\s*@{_STEP}\s*=\s*(['\"])")


def _plain_document(text: str | bytes) -> bool:
    if isinstance(text, bytes):
        if not text.isascii():
            return False
        text = text.decode("ascii")
    return not any(token in text for token in ("<!", "&", "\x00", "<?"))


class _XMLScope(TextValues):
    def tree(self, node: ast.expr, depth: int = 0) -> bool:
        if depth >= 12:
            return False
        if (value := self.assigned(node)) is not None:
            return self.tree(value, depth + 1)
        if not isinstance(node, ast.Call):
            return False
        if self.scope.resolve(node.func) in _LXML_TREES:
            return True
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"getroot", "getroottree"}
            and not node.args
            and not node.keywords
            and self.tree(node.func.value, depth + 1)
        )

    def factory(self, node: ast.expr, depth: int = 0) -> ast.Call | None:
        if depth >= 12:
            return None
        if (value := self.assigned(node)) is not None:
            return self.factory(value, depth + 1)
        return node if isinstance(node, ast.Call) else None

    def fixed(self, node: ast.expr, depth: int = 0) -> bool:
        if depth >= 16:
            return False
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str | bytes | int | float | bool) or node.value is None
        if (value := self.assigned(node)) is not None:
            return self.fixed(value, depth + 1)
        if self.stored_literal(node) is not None:
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.fixed(node.left, depth + 1) and self.fixed(node.right, depth + 1)
        if isinstance(node, ast.JoinedStr):
            return all(
                self.fixed(part.value, depth + 1)
                and (part.format_spec is None or self.fixed(part.format_spec, depth + 1))
                if isinstance(part, ast.FormattedValue)
                else isinstance(part, ast.Constant)
                for part in node.values
            )
        return False

    def quoted_value(self, node: ast.expr, depth: int = 0) -> bool:
        """Prove a single value stays within one simple XPath attribute literal."""
        if depth >= 12:
            return False
        if (value := self.assigned(node)) is not None:
            return self.quoted_value(value, depth + 1)
        if not isinstance(node, ast.JoinedStr) or len(node.values) != 3:
            return False
        prefix, field, suffix = node.values
        if not (
            isinstance(prefix, ast.Constant)
            and isinstance(prefix.value, str)
            and isinstance(suffix, ast.Constant)
            and isinstance(suffix.value, str)
            and isinstance(field, ast.FormattedValue)
            and field.conversion == -1
            and field.format_spec is None
            and (match := _QUOTED_ATTRIBUTE.fullmatch(prefix.value))
            and suffix.value.strip() == match[1] + "]"
        ):
            return False
        quote = match[1]
        fragment = field.value
        if isinstance(fragment, ast.Call) and isinstance(fragment.func, ast.Attribute):
            if fragment.func.attr != "replace" or fragment.keywords or len(fragment.args) != 2:
                return False
            old, new = fragment.args
            return (
                isinstance(old, ast.Constant)
                and old.value == quote
                and isinstance(new, ast.Constant)
                and isinstance(new.value, str)
                and quote not in new.value
                and self.string_value(fragment.func.value)
            )
        if (
            not isinstance(fragment, ast.Name)
            or not self.string_value(fragment)
            or self.in_loop(fragment)
        ):
            return False
        for guard in self.scope.nodes:
            if not isinstance(guard, ast.If) or not self.scope.precedes(guard, fragment):
                continue
            test = guard.test
            if (
                isinstance(test, ast.Compare)
                and len(test.ops) == 1
                and isinstance(test.ops[0], ast.In)
                and isinstance(test.left, ast.Constant)
                and test.left.value == quote
                and isinstance(test.comparators[0], ast.Name)
                and test.comparators[0].id == fragment.id
                and isinstance(guard.body[-1], ast.Return | ast.Raise)
                and not any(
                    guard.lineno <= write.lineno <= fragment.lineno
                    for write in self.stores.get(fragment.id, [])
                )
            ):
                return True
        return False

    def plain_xml_text(self, node: ast.expr, depth: int = 0) -> bool:
        if depth >= 16:
            return False
        if (value := self.assigned(node)) is not None:
            return self.plain_xml_text(value, depth + 1)
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            return _plain_document(node.value)
        choices = LiteralInputs(self).values(node)
        return (
            choices is not None
            and len(choices) > 0
            and all(_plain_document(text) for text in choices)
        )

    def parser_state(self, node: ast.expr, use: ast.Call) -> tuple[_Mode, int | None]:
        factory = self.factory(node)
        if (
            not factory
            or self.scope.resolve(factory.func) != "xml.sax.make_parser"
            or factory.args
            or factory.keywords
        ):
            return "parser_unknown", None
        if node is factory:
            return "entities_disabled", factory.lineno
        if not isinstance(node, ast.Name) or self.in_loop(use):
            return "parser_unknown", None

        # Consider all reads of the locally created parser and its simple aliases.
        # Passing it to an opaque helper also gives that helper control over features.
        aliases = {node.id}
        root = self.scope.parents[factory]
        if not isinstance(root, ast.Assign | ast.AnnAssign):
            return "parser_unknown", None
        targets = root.targets if isinstance(root, ast.Assign) else [root.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            return "parser_unknown", None
        aliases.add(targets[0].id)
        processed: set[str] = set()
        events: list[tuple[ast.Name, ast.Call | None]] = []
        while pending := aliases - processed:
            name = pending.pop()
            processed.add(name)
            if (
                len(processed) > 32
                or self.scope.definitions.get(name, 0) != 1
                or name in self.closed_over
            ):
                return "parser_unknown", None
            for read in self.loads.get(name, []):
                if read is node or read.lineno < factory.lineno or read.lineno > use.lineno:
                    continue
                if self.factory(read) is not factory:
                    continue
                parent = self.scope.parents[read]
                if (
                    isinstance(parent, ast.Assign)
                    and parent.value is read
                    and len(parent.targets) == 1
                    and isinstance(parent.targets[0], ast.Name)
                ):
                    aliases.add(parent.targets[0].id)
                    continue
                if isinstance(parent, ast.Attribute):
                    call = self.scope.parents[parent]
                    if (
                        isinstance(call, ast.Call)
                        and call.func is parent
                        and parent.attr == "setFeature"
                    ):
                        events.append((read, call))
                        continue
                events.append((read, None))
        state: _Mode = "entities_disabled"
        line: int | None = factory.lineno
        for read, feature in sorted(
            events, key=lambda event: (event[0].lineno, event[0].col_offset)
        ):
            if feature is None:
                return "parser_unknown", read.lineno
            if len(feature.args) != 2 or feature.keywords:
                state, line = "parser_unknown", read.lineno
                continue
            flag, value = feature.args
            flag_name = self.scope.resolve(flag)
            if flag_name != "xml.sax.handler.feature_external_ges" and not (
                isinstance(flag, ast.Constant) and flag.value == _ENTITY_FEATURE
            ):
                if flag_name.startswith("xml.sax.handler.feature_") or isinstance(
                    flag, ast.Constant
                ):
                    continue
                state, line = "parser_unknown", feature.lineno
                continue
            statement = self.scope.parents[feature]
            if (
                isinstance(statement, ast.Expr)
                and self.scope.precedes(statement, use)
                and isinstance(value, ast.Constant)
                and type(value.value) is bool
            ):
                state = "entities_enabled" if value.value else "entities_disabled"
            else:
                state = "parser_unknown"
            line = feature.lineno
        return state, line

    def invocation(self, call: ast.Call) -> XMLInvocation | None:
        api = self.scope.resolve(call.func)
        query_param = _XPATH_ARGUMENTS.get(api)
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr == "xpath"
            and self.tree(call.func.value)
        ):
            api, query_param = "lxml.etree.xpath", (0, "_path")
        if query_param:
            if selected := call_argument(call, *query_param):
                return XMLInvocation(
                    api=api,
                    argument_index=selected[0],
                    mode="xpath",
                    fixed_input=self.fixed(selected[1]),
                    quoted_value_constrained=self.quoted_value(selected[1]),
                )
            return None
        if api in _DOM_INPUTS:
            selected = call_argument(call, 0, _DOM_INPUTS[api])
            if selected is None:
                return None
            parser = call_argument(call, 1, "parser")
            if parser is None or isinstance(parser[1], ast.Constant) and parser[1].value is None:
                state: _Mode = "entities_disabled"
                line: int | None = None
            else:
                state, line = self.parser_state(parser[1], call)
        elif isinstance(call.func, ast.Attribute) and call.func.attr == "parse":
            parser_factory = self.factory(call.func.value)
            if (
                parser_factory is None
                or self.scope.resolve(parser_factory.func) != "xml.sax.make_parser"
            ):
                return None
            selected = call_argument(call, 0, "source")
            if selected is None:
                return None
            api = "xml.sax.xmlreader.XMLReader.parse"
            state, line = self.parser_state(call.func.value, call)
        else:
            return None
        return XMLInvocation(
            api=api,
            argument_index=selected[0],
            mode=state,
            configuration_line=line,
            fixed_input=api.endswith(".parseString") and self.plain_xml_text(selected[1]),
        )


def xml_calls(source: bytes) -> dict[_Position, XMLInvocation]:
    if b"xml" not in source and b"elementpath" not in source:
        return {}
    return dict(_invocations(source))


def _invocations(source: bytes) -> Iterator[tuple[_Position, XMLInvocation]]:
    for scope in python_scopes(source):
        local = _XMLScope(scope)
        for node in scope.nodes:
            if isinstance(node, ast.Call) and (fact := local.invocation(node)) is not None:
                if node.end_lineno is not None and node.end_col_offset is not None:
                    yield (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset), fact
