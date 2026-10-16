"""Tool JSON Schema simplification and validation for strict Gemini function calling."""

from __future__ import annotations

import copy
from typing import Any

ALLOWED_SCHEMA_KEYS: set[str] = {
    "type",
    "properties",
    "required",
    "enum",
    "items",
    "description",
    "minimum",
    "maximum",
}


def _inline_references(node: Any, root_defs: dict[str, Any]) -> Any:
    """Recursively inline $ref pointers using definitions found in root $defs."""
    if isinstance(node, dict):
        if "$ref" in node:
            ref_path: str = node["$ref"]
            parts = [p for p in ref_path.lstrip("#").split("/") if p]
            lookup: Any = root_defs
            for part in parts:
                if isinstance(lookup, dict) and part in lookup:
                    lookup = lookup[part]
                else:
                    lookup = None
                    break
            if lookup is not None:
                return _inline_references(copy.deepcopy(lookup), root_defs)
            return node

        return {k: _inline_references(v, root_defs) for k, v in node.items()}

    if isinstance(node, list):
        return [_inline_references(item, root_defs) for item in node]

    return node


def simplify_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Simplify JSON Schema per Spec 04 Section 10.2.1.

    Inlines $defs/$ref, unrolls nullable anyOf unions, deletes title and default keys,
    and preserves only canonical Gemini-supported properties.
    """
    cloned: dict[str, Any] = copy.deepcopy(schema)
    defs_store: dict[str, Any] = {}
    if "$defs" in cloned and isinstance(cloned["$defs"], dict):
        extracted_defs = cloned.pop("$defs")
        defs_store["$defs"] = extracted_defs
        defs_store.update(extracted_defs)
    if "definitions" in cloned and isinstance(cloned["definitions"], dict):
        extracted_definitions = cloned.pop("definitions")
        defs_store["definitions"] = extracted_definitions
        defs_store.update(extracted_definitions)

    inlined: Any = _inline_references(cloned, defs_store)
    return _clean_node(inlined)


def _clean_node(node: Any) -> Any:
    """Recursively strip unapproved schema keys and flatten anyOf nullables."""
    if isinstance(node, list):
        return [_clean_node(item) for item in node]

    if not isinstance(node, dict):
        return node

    # Convert anyOf: [X, {type: null}] to X
    if "anyOf" in node and isinstance(node["anyOf"], list):
        non_null_candidates = [
            cand for cand in node["anyOf"]
            if isinstance(cand, dict) and cand.get("type") not in ("null", None)
        ]
        if len(non_null_candidates) == 1:
            preserved_desc = node.get("description")
            simplified = _clean_node(non_null_candidates[0])
            if preserved_desc and "description" not in simplified:
                simplified["description"] = preserved_desc
            return simplified

    cleaned: dict[str, Any] = {}
    for key, val in node.items():
        if key not in ALLOWED_SCHEMA_KEYS:
            continue

        if key == "properties" and isinstance(val, dict):
            cleaned["properties"] = {
                prop_name: _clean_node(prop_schema)
                for prop_name, prop_schema in val.items()
            }
        elif key == "items":
            cleaned["items"] = _clean_node(val)
        else:
            cleaned[key] = val

    # Ensure root objects have explicit type: 'object'
    if "properties" in cleaned and "type" not in cleaned:
        cleaned["type"] = "object"

    return cleaned


def assert_simple_schema(schema: dict[str, Any], path: str = "") -> None:
    """Assert that a schema contains only allowed keys and no prohibited constructs."""
    if not isinstance(schema, dict):
        return

    for key, val in schema.items():
        current_path: str = f"{path}.{key}" if path else key
        if key not in ALLOWED_SCHEMA_KEYS:
            raise ValueError(
                f"Schema contains prohibited key '{key}' at '{current_path}'. "
                f"Allowed keys are: {sorted(ALLOWED_SCHEMA_KEYS)}"
            )

        if key == "properties" and isinstance(val, dict):
            for prop_name, prop_val in val.items():
                if isinstance(prop_val, dict):
                    assert_simple_schema(prop_val, f"{current_path}.{prop_name}")
        elif key == "items" and isinstance(val, dict):
            assert_simple_schema(val, current_path)
