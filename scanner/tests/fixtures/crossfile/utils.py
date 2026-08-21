"""Utility functions for input validation."""


def validate_input(data):
    if data is None or data.strip() == "":
        raise ValueError("empty input")
    if len(data) > 1000:
        raise ValueError("input too long")
    return data.strip()


def sanitize_html(text):
    import html

    return html.escape(text)
