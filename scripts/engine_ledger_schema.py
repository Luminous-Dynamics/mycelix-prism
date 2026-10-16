#!/usr/bin/env python3
"""Strict validator for the JSON Schema keyword subset used by Prism's ledger.

This deliberately is not advertised as a general JSON Schema implementation.
It accepts only the keywords Prism currently uses and fails closed if the
contract begins using a keyword this dependency-free validator cannot enforce.
"""
from __future__ import annotations

import json
import re
from datetime import date
from urllib.parse import urlsplit
from typing import Any

SUPPORTED_KEYWORDS = {
    "$schema", "title", "description", "type", "additionalProperties",
    "required", "properties", "items", "const", "enum", "allOf", "if", "then",
    "format", "minLength", "minItems", "uniqueItems", "pattern",
}
SUPPORTED_TYPES = {"null", "boolean", "object", "array", "string", "number", "integer"}
SUPPORTED_FORMATS = {"date", "uri"}


def validate_schema_definition(schema: Any, path: str = "$schema") -> list[str]:
    """Validate schema structure and reject unsupported keywords before use."""
    errors: list[str] = []
    if not isinstance(schema, dict):
        return [f"{path} must be a schema object"]

    unknown = sorted(set(schema) - SUPPORTED_KEYWORDS)
    for keyword in unknown:
        errors.append(f"{path} uses unsupported schema keyword: {keyword}")

    for key in ("title", "description", "$schema"):
        if key in schema and not isinstance(schema[key], str):
            errors.append(f"{path}.{key} must be a string")

    if "type" in schema:
        declared = schema["type"]
        types = declared if isinstance(declared, list) else [declared]
        if not types or any(not isinstance(item, str) or item not in SUPPORTED_TYPES for item in types):
            errors.append(f"{path}.type contains an unsupported type")

    if "required" in schema:
        required = schema["required"]
        if (not isinstance(required, list)
                or any(not isinstance(item, str) for item in required)
                or len(required) != len(set(required))):
            errors.append(f"{path}.required must be a list of unique strings")

    if "properties" in schema:
        properties = schema["properties"]
        if not isinstance(properties, dict):
            errors.append(f"{path}.properties must be an object")
        else:
            for name, child in properties.items():
                errors.extend(validate_schema_definition(child, f"{path}.properties.{name}"))

    if "items" in schema:
        errors.extend(validate_schema_definition(schema["items"], f"{path}.items"))

    if "additionalProperties" in schema:
        additional = schema["additionalProperties"]
        if not isinstance(additional, (bool, dict)):
            errors.append(f"{path}.additionalProperties must be boolean or a schema")
        elif isinstance(additional, dict):
            errors.extend(validate_schema_definition(additional, f"{path}.additionalProperties"))

    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        errors.append(f"{path}.enum must be a non-empty list")
    if "allOf" in schema:
        clauses = schema["allOf"]
        if not isinstance(clauses, list) or not clauses:
            errors.append(f"{path}.allOf must be a non-empty list")
        else:
            for index, child in enumerate(clauses):
                errors.extend(validate_schema_definition(child, f"{path}.allOf[{index}]"))
    for keyword in ("if", "then"):
        if keyword in schema:
            errors.extend(validate_schema_definition(schema[keyword], f"{path}.{keyword}"))

    if "format" in schema and schema["format"] not in SUPPORTED_FORMATS:
        errors.append(f"{path}.format is unsupported: {schema['format']}")
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            errors.append(f"{path}.pattern must be a string")
        else:
            try:
                re.compile(schema["pattern"])
            except re.error as exc:
                errors.append(f"{path}.pattern is invalid: {exc}")
    for keyword in ("minLength", "minItems"):
        if keyword in schema and (
            isinstance(schema[keyword], bool)
            or not isinstance(schema[keyword], int)
            or schema[keyword] < 0
        ):
            errors.append(f"{path}.{keyword} must be a non-negative integer")
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        errors.append(f"{path}.uniqueItems must be boolean")
    if "const" in schema:
        pass
    return errors


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _validate_format(value: str, fmt: str) -> bool:
    if fmt == "date":
        try:
            parsed = date.fromisoformat(value)
            return parsed.isoformat() == value
        except ValueError:
            return False
    if fmt == "uri":
        if any(character.isspace() for character in value):
            return False
        try:
            parsed = urlsplit(value)
        except ValueError:
            return False
        return bool(parsed.scheme and (parsed.scheme.lower() not in {"http", "https"} or parsed.netloc))
    return False


def validate_instance(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Validate an instance against the currently supported schema subset."""
    errors: list[str] = []
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_matches_type(value, item) for item in types):
            return [f"{path} does not match declared type {schema['type']}"]

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path} must equal the declared const")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path} is not an allowed enum value")

    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path} is missing required property: {key}")
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, child_schema in properties.items():
                if key in value:
                    errors.extend(validate_instance(value[key], child_schema, f"{path}.{key}"))
        additional = schema.get("additionalProperties", True)
        extra_keys = set(value) - set(properties if isinstance(properties, dict) else {})
        if additional is False:
            for key in sorted(extra_keys):
                errors.append(f"{path} contains forbidden additional property: {key}")
        elif isinstance(additional, dict):
            for key in sorted(extra_keys):
                errors.extend(validate_instance(value[key], additional, f"{path}.{key}"))

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path} has fewer than {schema['minItems']} items")
        if schema.get("uniqueItems") is True:
            fingerprints = [json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for item in value]
            if len(fingerprints) != len(set(fingerprints)):
                errors.append(f"{path} items are not unique")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(validate_instance(item, item_schema, f"{path}[{index}]"))

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path} is shorter than minLength {schema['minLength']}")
        if "pattern" in schema and isinstance(schema["pattern"], str) and not re.search(schema["pattern"], value):
            errors.append(f"{path} does not match required pattern {schema['pattern']}")
        fmt = schema.get("format")
        if fmt and not _validate_format(value, fmt):
            errors.append(f"{path} does not match format {fmt}")

    for index, clause in enumerate(schema.get("allOf", [])):
        errors.extend(validate_instance(value, clause, f"{path}.allOf[{index}]"))
    if isinstance(schema.get("if"), dict):
        if_errors = validate_instance(value, schema["if"], path)
        if not if_errors and isinstance(schema.get("then"), dict):
            errors.extend(validate_instance(value, schema["then"], path))
    return errors


def validate_json_schema(schema: Any, value: Any) -> list[str]:
    """Validate schema support first, then validate an instance; fail closed."""
    schema_errors = validate_schema_definition(schema)
    if schema_errors:
        return [f"schema contract error: {error}" for error in schema_errors]
    return validate_instance(value, schema)
