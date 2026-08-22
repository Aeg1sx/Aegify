"""Linear-time source text normalization helpers."""

from __future__ import annotations


def scrub_quoted_strings(text: str) -> str:
    """Replace single- and double-quoted string contents while preserving offsets."""
    characters = list(text)
    quote: str | None = None
    escaped = False

    for index, character in enumerate(characters):
        if quote is None:
            if character in {"'", '"'}:
                quote = character
                characters[index] = " "
            continue

        characters[index] = " "
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == quote:
            quote = None

    return "".join(characters)
