"""Strict registry schema subset used by the migrated validator.

All schemas are server-owned. Unknown keywords fail registry construction rather
than silently weakening validation. This avoids an additional runtime dependency.
"""
from types import SimpleNamespace
from .drift_runtime import _validate_value


class Draft202012Validator:
    _keys = {"type", "properties", "required", "additionalProperties", "items", "enum",
             "const", "minLength", "maxLength", "pattern", "minimum", "maximum", "description"}

    @classmethod
    def check_schema(cls, schema):
        if not isinstance(schema, dict) or set(schema) - cls._keys:
            raise ValueError("unsupported registry schema")
        for child in schema.get("properties", {}).values():
            cls.check_schema(child)
        if "items" in schema:
            cls.check_schema(schema["items"])

    def __init__(self, schema):
        self.check_schema(schema)
        self.schema = schema

    def iter_errors(self, instance):
        return [SimpleNamespace(message=e) for e in _validate_value(instance, self.schema, "$")]
