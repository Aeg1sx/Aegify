"""Read physical source positions of Java properties in Spring Boot configuration."""

import re
from collections.abc import Iterator

_SPACE = " \t\f"
_PAIR = re.compile(r"((?:\\.|[^\\:= \t\f])+)(?:[ \t\f]*[=:][ \t\f]*|[ \t\f]+|$)(.*)")
_ESCAPE = re.compile(r"\\(?:u([0-9a-fA-F]{4})|(.))")
_SPECIAL = {"t": "\t", "n": "\n", "r": "\r", "f": "\f"}


def _unescape(value: str) -> str:
    def convert(match: re.Match[str]) -> str:
        if match[1]:
            return chr(int(match[1], 16))
        if match[2] == "u":
            raise ValueError("invalid_unicode_escape")
        return _SPECIAL.get(match[2], match[2])

    return _ESCAPE.sub(convert, value)


def property_entries(raw: bytes) -> Iterator[tuple[int, int, str, str]]:
    # java.util.Properties' byte-stream format is ISO-8859-1 with Unicode escapes.
    lines = re.split(r"\r\n|\r|\n", raw.decode("iso-8859-1"))
    if len(lines) > 20_000:
        raise ValueError("properties_line_limit")
    document = 1
    index = 0
    while index < len(lines):
        offset = index
        line = lines[offset]
        index += 1
        if line in {"#---", "!---"}:
            previous = lines[offset - 1] if offset > 0 else ""
            following = lines[index] if index < len(lines) else ""
            if not any(
                neighbor.lstrip(_SPACE).startswith(line[0]) for neighbor in (previous, following)
            ):
                document += 1
        logical = line.lstrip(_SPACE)
        if not logical or logical.startswith(("#", "!")):
            continue
        parts = []
        while (len(logical) - len(logical.rstrip("\\"))) % 2:
            parts.append(logical[:-1])
            if index == len(lines):
                logical = ""
                break
            logical = lines[index].lstrip(_SPACE)
            index += 1
        logical = "".join((*parts, logical))
        if len(logical) > 65_536:
            raise ValueError("properties_line_limit")
        pair = _PAIR.fullmatch(logical)
        if pair:
            yield document, offset + 1, _unescape(pair[1]), _unescape(pair[2])
