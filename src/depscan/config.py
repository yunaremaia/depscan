"""Configuration profiles and validation for depscan."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


PROFILES: dict[str, dict[str, Any]] = {
    "relaxed": {
        "typosquat": True,
        "output_format": "text",
        "exclude": [],
    },
    "strict": {
        "typosquat": True,
        "output_format": "text",
        "fail_on": "any",
        "exclude": [],
    },
    "ci": {
        "typosquat": True,
        "output_format": "sarif",
        "fail_on": "any",
        "exclude": [],
    },
}

ALLOWED_KEYS = {"typosquat", "output_format", "fail_on", "exclude"}
OUTPUT_FORMATS = {"text", "json", "markdown", "sarif"}
FAIL_ON_VALUES = {"typosquat", "vulnerable", "any"}


def render_profile(profile: str) -> str:
    """Render a named starter profile as YAML."""
    return yaml.safe_dump(PROFILES[profile], sort_keys=False)


def validate_config(data: Any) -> dict[str, Any]:
    """Validate the supported .depscan.yml structure."""
    if not isinstance(data, dict):
        raise ValueError("configuration must be a mapping")
    unknown = set(data) - ALLOWED_KEYS
    if unknown:
        raise ValueError(f"unknown option: {sorted(unknown)[0]}")
    if "typosquat" in data and not isinstance(data["typosquat"], bool):
        raise ValueError("typosquat must be true or false")
    if data.get("output_format") not in OUTPUT_FORMATS:
        raise ValueError("output_format must be text, json, markdown, or sarif")
    if "fail_on" in data and data["fail_on"] not in FAIL_ON_VALUES:
        raise ValueError("fail_on must be typosquat, vulnerable, or any")
    if "exclude" in data and (
        not isinstance(data["exclude"], list)
        or not all(isinstance(item, str) for item in data["exclude"])
    ):
        raise ValueError("exclude must be a list of strings")
    return data


def load_config(path: str | Path) -> dict[str, Any]:
    """Load and validate a YAML configuration file."""
    config_path = Path(path)
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    return validate_config(data)
