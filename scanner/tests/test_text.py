"""Tests for bounded source text normalization."""

from aegify.text import scrub_quoted_strings


def test_scrub_quoted_strings_preserves_offsets_and_escapes() -> None:
    source = "safe = 'secret\\' value'; used = request.value"
    scrubbed = scrub_quoted_strings(source)

    assert len(scrubbed) == len(source)
    assert "secret" not in scrubbed
    assert "request.value" in scrubbed
    assert scrubbed.index("request.value") == source.index("request.value")


def test_scrub_quoted_strings_bounds_unterminated_input() -> None:
    source = 'prefix = "' + ("a" * 500_000)
    scrubbed = scrub_quoted_strings(source)

    assert scrubbed.startswith("prefix =  ")
    assert scrubbed.strip() == "prefix ="
