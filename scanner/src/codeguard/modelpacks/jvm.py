"""Strict loader and matcher for the bundled JVM library summary pack."""

from __future__ import annotations

import re
from importlib.resources import files
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from codeguard.models import CallSite, Language


class JvmLibraryModel(BaseModel):
    """One declarative external-library taint effect."""

    model_config = ConfigDict(extra="forbid")

    id: str
    role: Literal["source", "sink", "propagator", "sanitizer"]
    languages: list[Language] = Field(min_length=1)
    callee: str
    receiver_types: list[str] = Field(default_factory=list)
    inputs: list[str] = Field(default_factory=list)
    outputs: list[Literal["return", "receiver"]] = Field(default_factory=list)
    source_type: str | None = None
    sink_type: str | None = None
    argument_index: int = Field(default=0, ge=0)
    sanitizes: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", value):
            raise ValueError("model id must be lowercase and filesystem-safe")
        return value

    @field_validator("languages")
    @classmethod
    def validate_languages(cls, value: list[Language]) -> list[Language]:
        unsupported = set(value) - {Language.JAVA, Language.KOTLIN}
        if unsupported:
            raise ValueError("JVM models only support java and kotlin")
        return value

    @field_validator("inputs")
    @classmethod
    def validate_inputs(cls, value: list[str]) -> list[str]:
        for selector in value:
            if selector in {"receiver", "arguments"}:
                continue
            if re.fullmatch(r"argument:[0-9]+", selector):
                continue
            raise ValueError(f"unsupported taint input selector: {selector}")
        return value

    @model_validator(mode="after")
    def validate_role_contract(self) -> JvmLibraryModel:
        if self.role == "source":
            if not self.source_type or self.outputs != ["return"]:
                raise ValueError("source models require source_type and return output")
        elif self.role == "sink":
            if not self.sink_type or self.outputs:
                raise ValueError("sink models require sink_type and no outputs")
        else:
            if not self.inputs or not self.outputs:
                raise ValueError(f"{self.role} models require inputs and outputs")
        if self.role == "sanitizer" and not self.sanitizes:
            raise ValueError("sanitizer models require at least one sink category")
        if self.role != "sanitizer" and self.sanitizes:
            raise ValueError("sanitizes is only valid for sanitizer models")
        return self

    def matches(
        self,
        call: CallSite,
        language: Language,
        receiver_objects: set[str],
    ) -> bool:
        if language not in self.languages or call.callee != self.callee:
            return False
        if not self.receiver_types:
            return True
        receiver = call.receiver or ""
        candidates = {receiver, receiver.rsplit(".", 1)[-1], *receiver_objects}
        for expected in self.receiver_types:
            simple = expected.rsplit(".", 1)[-1]
            if any(
                candidate == expected
                or candidate == simple
                or candidate.endswith(f":{expected}")
                or candidate.endswith(f":{simple}")
                for candidate in candidates
            ):
                return True
        return False


class JvmModelPack(BaseModel):
    """A versioned, schema-validated collection of JVM taint summaries."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int
    pack_version: str
    ecosystem: Literal["jvm"]
    models: list[JvmLibraryModel]

    @model_validator(mode="after")
    def validate_pack(self) -> JvmModelPack:
        if self.schema_version != 1:
            raise ValueError(f"unsupported JVM model schema: {self.schema_version}")
        if not re.fullmatch(r"[0-9]{4}\.[0-9]{2}\.[0-9]+", self.pack_version):
            raise ValueError("pack_version must use YYYY.MM.patch")
        ids = [model.id for model in self.models]
        if len(ids) != len(set(ids)):
            raise ValueError("JVM model ids must be unique")
        return self


def load_jvm_model_pack(path: Path | None = None) -> JvmModelPack:
    """Load the bundled pack, or a supplied pack for validation/testing."""

    if path is None:
        resource = files("codeguard.modelpacks").joinpath("jvm.yml")
        payload = yaml.safe_load(resource.read_text(encoding="utf-8")) or {}
    else:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return JvmModelPack.model_validate(payload)
