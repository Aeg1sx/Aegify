"""Schema and distribution tests for the JVM semantic model pack."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from aegify.modelpacks import load_jvm_model_pack


def test_bundled_jvm_model_pack_is_strict_and_versioned():
    pack = load_jvm_model_pack()

    assert pack.schema_version == 1
    assert pack.pack_version == "2026.08.1"
    assert len(pack.models) >= 9
    assert {model.role for model in pack.models} == {
        "source",
        "sink",
        "propagator",
        "sanitizer",
    }


def test_jvm_model_pack_rejects_unknown_fields(tmp_path: Path):
    invalid = tmp_path / "invalid.yml"
    invalid.write_text(
        'schema_version: 1\npack_version: "2026.08.1"\necosystem: jvm\nunknown: true\nmodels: []\n'
    )

    with pytest.raises(ValidationError):
        load_jvm_model_pack(invalid)
