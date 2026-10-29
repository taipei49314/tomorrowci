#!/usr/bin/env python3
"""Static and fixture tests for the version-1 TomorrowCI config schema.

The test deliberately uses only the Python standard library so the schema
contract remains testable in release and CI environments without a pip install.
"""

from __future__ import annotations

import copy
import json
import math
import re
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "packages" / "schema" / "tomorrowci-config.schema.json"
U32_MAX = 4_294_967_295
U64_MAX = 18_446_744_073_709_551_615


class SchemaContractError(ValueError):
    """Raised when a fixture violates the supported schema contract."""


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            or isinstance(value, float)
            and math.isfinite(value)
            and value.is_integer()
        )
    if expected == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
        )
    if expected == "null":
        return value is None
    raise AssertionError(f"test validator does not implement JSON Schema type {expected!r}")


def _resolve_ref(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise AssertionError(f"test validator only supports local references: {reference}")
    resolved: Any = root
    for token in reference[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        resolved = resolved[token]
    if not isinstance(resolved, dict):
        raise AssertionError(f"schema reference does not resolve to an object: {reference}")
    return resolved


def validate_fixture(
    value: Any,
    schema: dict[str, Any],
    root: dict[str, Any] | None = None,
    path: str = "$",
) -> None:
    """Validate the keyword subset used by this repository's schema."""

    root = schema if root is None else root
    if "$ref" in schema:
        validate_fixture(value, _resolve_ref(root, schema["$ref"]), root, path)

    expected_types = schema.get("type")
    if isinstance(expected_types, str):
        expected_types = [expected_types]
    if expected_types is not None and not any(
        _matches_type(value, expected) for expected in expected_types
    ):
        raise SchemaContractError(
            f"{path}: expected {'|'.join(expected_types)}, got {type(value).__name__}"
        )

    if "const" in schema and value != schema["const"]:
        raise SchemaContractError(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaContractError(f"{path}: {value!r} is not in {schema['enum']!r}")
    if isinstance(value, str) and "pattern" in schema:
        if re.search(schema["pattern"], value) is None:
            raise SchemaContractError(f"{path}: does not match {schema['pattern']!r}")

    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    ):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaContractError(f"{path}: below minimum {schema['minimum']}")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            raise SchemaContractError(
                f"{path}: not above exclusive minimum {schema['exclusiveMinimum']}"
            )
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaContractError(f"{path}: above maximum {schema['maximum']}")

    if isinstance(value, list) and "items" in schema:
        if schema.get("uniqueItems") and any(
            item in value[:index] for index, item in enumerate(value)
        ):
            raise SchemaContractError(f"{path}: duplicate array items")
        for index, item in enumerate(value):
            validate_fixture(item, schema["items"], root, f"{path}[{index}]")

    if not isinstance(value, dict):
        return

    for required in schema.get("required", []):
        if required not in value:
            raise SchemaContractError(f"{path}: missing required property {required!r}")

    properties = schema.get("properties", {})
    patterns = schema.get("patternProperties", {})
    for key, item in value.items():
        child_path = f"{path}.{key}"
        if key in properties:
            validate_fixture(item, properties[key], root, child_path)
            continue
        matching = [rule for pattern, rule in patterns.items() if re.search(pattern, key)]
        if matching:
            for rule in matching:
                validate_fixture(item, rule, root, child_path)
            continue
        if schema.get("additionalProperties") is False:
            raise SchemaContractError(f"{path}: unexpected property {key!r}")


class ConfigSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load_schema()
        cls.defs = cls.schema["$defs"]

    def assert_valid(self, fixture: dict[str, Any]) -> None:
        validate_fixture(fixture, self.schema)

    def assert_invalid(self, fixture: dict[str, Any]) -> None:
        with self.assertRaises(SchemaContractError):
            validate_fixture(fixture, self.schema)

    def test_schema_is_closed_and_models_every_rust_config_section(self) -> None:
        self.assertEqual(
            self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertEqual(self.schema["required"], ["version"])
        self.assertIs(self.schema["additionalProperties"], False)
        self.assertEqual(set(self.schema["patternProperties"]), {"^x[-_]"})
        self.assertEqual(
            set(self.schema["properties"]),
            {
                "version",
                "project",
                "baseline",
                "candidates",
                "execution",
                "sandbox",
                "report",
                "policy",
            },
        )
        for name in (
            "project",
            "baseline",
            "candidates",
            "runtimeCandidates",
            "dependencyCandidates",
            "execution",
            "sandbox",
            "report",
            "policy",
            "failIfPolicy",
        ):
            self.assertIs(
                self.defs[name]["additionalProperties"],
                False,
                f"{name} must reject misspelled or unbound properties",
            )

    def test_numeric_bounds_and_sandbox_enums_match_rust_validation(self) -> None:
        execution = self.defs["execution"]["properties"]
        for field in ("max_scenarios", "timeout_seconds", "reruns_on_failure", "max_parallel"):
            self.assertEqual(execution[field]["minimum"], 1)
        self.assertEqual(execution["timeout_seconds"]["maximum"], U64_MAX)
        for field in ("max_scenarios", "reruns_on_failure", "max_parallel"):
            self.assertEqual(execution[field]["maximum"], U32_MAX)

        sandbox = self.defs["sandbox"]["properties"]
        self.assertEqual(sandbox["engine"]["enum"], ["auto", "docker", "podman"])
        self.assertEqual(sandbox["network"]["enum"], ["fetch-only"])
        self.assertEqual(sandbox["memory_mb"]["minimum"], 1)
        self.assertEqual(sandbox["pids_limit"]["minimum"], 1)
        self.assertEqual(sandbox["cpus"]["exclusiveMinimum"], 0)

    def test_minimal_defaults_and_complete_config_are_valid(self) -> None:
        self.assert_valid({"version": 1})
        self.assert_valid(
            {
                "version": 1,
                "project": {
                    "ecosystem": "python",
                    "test_command": "python -m pytest -q",
                    "build_command": "auto",
                    "python_image_pip": True,
                },
                "baseline": {"runtime": "3.11", "dependencies": "locked"},
                "candidates": {
                    "runtime": {
                        "channels": ["stable", "preview"],
                        "max_versions": 5,
                        "versions": ["3.12", "3.14"],
                    },
                    "dependencies": {
                        "latest_allowed": True,
                        "prerelease": False,
                    },
                },
                "execution": {
                    "max_scenarios": 24,
                    "timeout_seconds": 900,
                    "reruns_on_failure": 2,
                    "max_parallel": 2,
                },
                "sandbox": {
                    "engine": "podman",
                    "network": "fetch-only",
                    "memory_mb": 4096,
                    "cpus": 1.5,
                    "pids_limit": 512,
                },
                "report": {"html": True, "json": True, "sarif": False},
                "policy": {
                    "fail_if": {
                        "baseline_invalid": True,
                        "new_future_failure": True,
                        "horizon_regression": False,
                        "blocked_ratio_above": 0.25,
                    }
                },
                "x-experimental": {"enabled": True},
                "x_internal": "opaque extension payload",
            }
        )
        self.assert_valid({"version": 1, "policy": None})
        self.assert_valid(
            {"version": 1, "candidates": {"runtime": {"max_versions": 0}}}
        )

    def test_invalid_types_versions_and_unknown_properties_are_rejected(self) -> None:
        invalid = [
            {},
            {"version": 2},
            {"version": 1, "unknown": True},
            {"version": 1, "project": {"ecosytem": "python"}},
            {"version": 1, "project": {"ecosystem": "pyhton"}},
            {"version": 1, "project": {"build_command": "make build"}},
            {"version": 1, "project": {"python_image_pip": "true"}},
            {"version": 1, "baseline": {"runtime": 311}},
            {"version": 1, "candidates": {"runtime": {"channels": ["stable", 3]}}},
            {"version": 1, "candidates": {"dependencies": {"latest": True}}},
            {"version": 1, "execution": {"timeout_seconds": "900"}},
            {"version": 1, "sandbox": {"memory_mb": 1.5}},
            {"version": 1, "report": {"html": "true"}},
            {"version": 1, "policy": {"fail_if": {"unknown": False}}},
        ]
        for fixture in invalid:
            with self.subTest(fixture=fixture):
                self.assert_invalid(fixture)

    def test_zero_resources_invalid_engine_and_network_are_rejected(self) -> None:
        invalid_paths = [
            ("execution", "max_scenarios", 0),
            ("execution", "timeout_seconds", 0),
            ("execution", "reruns_on_failure", 0),
            ("execution", "max_parallel", 0),
            ("sandbox", "memory_mb", 0),
            ("sandbox", "cpus", 0),
            ("sandbox", "cpus", -1),
            ("sandbox", "pids_limit", 0),
            ("sandbox", "engine", "containerd"),
            ("sandbox", "network", "none"),
        ]
        for section, field, value in invalid_paths:
            fixture = {"version": 1, section: {field: value}}
            with self.subTest(section=section, field=field, value=value):
                self.assert_invalid(fixture)

    def test_rust_integer_widths_are_enforced(self) -> None:
        fixtures = [
            {"version": 1, "execution": {"max_scenarios": U32_MAX + 1}},
            {"version": 1, "execution": {"timeout_seconds": U64_MAX + 1}},
            {"version": 1, "candidates": {"runtime": {"max_versions": -1}}},
            {"version": 1, "sandbox": {"memory_mb": U32_MAX + 1}},
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                self.assert_invalid(copy.deepcopy(fixture))

    def test_explicit_runtime_versions_shape(self) -> None:
        for versions in ([], ["3.14"], ["3.9", "3.10"], ["3.999"]):
            self.assert_valid({"version": 1, "candidates": {"runtime": {"versions": versions}}})
        for versions in (
            None, "3.14", [3.14], [True], ["3.14", "3.14"], ["3.014"],
            ["3.14.0"], ["python:3.14"], ["3.14-slim"], ["3.14;id"],
            ["3.14/evil"], ["3.14 "], ["3.14\n"], ["4.0"], ["3.1000"],
        ):
            with self.subTest(versions=versions):
                self.assert_invalid({"version": 1, "candidates": {"runtime": {"versions": versions}}})
        # Semantic order, baseline comparison and cross-field budgets are checked
        # by Config/PythonAdapter tests, not by this structural JSON schema.


if __name__ == "__main__":
    unittest.main()
