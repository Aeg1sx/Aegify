import pytest

from aegify.scanner.engine import ScanEngine


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ("target, 'cache.bin'", True),
        ("filename='cache.bin', url=target", True),
        ("f'https://{target}/cover'", True),
        ("'https://images.example/' + target", False),
        ("url=f'https://images.example/{target}'", False),
        ("'https://images.example/cover', filename=target", False),
        ("'https://images.example/cover', data=target", False),
        ("'https://images.example' + target", True),
        ("**options", False),
    ],
)
def test_download_url_is_distinct_from_local_name_and_post_data(tmp_path, arguments, expected):
    source = tmp_path / "download.py"
    source.write_text(
        "from urllib.request import urlretrieve as download\n"
        "from flask import request\n"
        "def avatar():\n"
        "    target = request.form.get('avatar')\n"
        f"    return download({arguments})\n"
    )
    hits = [f for f in ScanEngine().scan_files(tmp_path, [source]).findings if f.cwe_id == 918]
    assert [(f.rule_id, f.line_start, f.taint_flow.source.line) for f in hits] == (
        [("AEG-SSRF-001", 5, 4)] if expected else []
    )


def test_local_download_module(tmp_path):
    source = tmp_path / "views.py"
    source.write_text(
        "from urllib.request import urlretrieve\n"
        "def view(request):\n    return urlretrieve(request.GET.get('avatar'))\n"
    )
    shadow = tmp_path / "urllib.py"
    shadow.write_text("request = None\n")
    assert not any(
        f.cwe_id == 918 for f in ScanEngine().scan_files(tmp_path, [source, shadow]).findings
    )
