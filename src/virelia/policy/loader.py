"""YAML policy loading with human-readable errors."""

from __future__ import annotations

import importlib.resources
from collections.abc import Iterable
from pathlib import Path

import yaml
from pydantic import ValidationError

from virelia.detectors import known_entity_types
from virelia.policy.schema import Policy


class PolicyError(ValueError):
    pass


def _render_validation_error(err: ValidationError, source: str) -> str:
    lines = [f"invalid policy ({source}):"]
    for e in err.errors():
        loc = ".".join(str(part) for part in e["loc"]) or "<root>"
        lines.append(f"  - {loc}: {e['msg']}")
    return "\n".join(lines)


def _validate_entities(policy: Policy, extra_entities: Iterable[str], source: str) -> None:
    known = known_entity_types() | set(extra_entities)
    for rule in policy.rules:
        unknown = sorted(set(rule.entities) - known)
        if unknown:
            raise PolicyError(
                f"invalid policy ({source}): rule {rule.id!r} references unknown "
                f"entities {unknown}. Known entities: {sorted(known)}"
            )


def parse_policy(
    data: object, *, source: str = "<dict>", extra_entities: Iterable[str] = ()
) -> Policy:
    # Tolerate a top-level `policy:` wrapper key.
    if isinstance(data, dict) and set(data) == {"policy"}:
        data = data["policy"]
    try:
        policy = Policy.model_validate(data)
    except ValidationError as err:
        raise PolicyError(_render_validation_error(err, source)) from err
    _validate_entities(policy, extra_entities, source)
    return policy


def load_policy(path: str | Path, *, extra_entities: Iterable[str] = ()) -> Policy:
    path = Path(path)
    data = yaml.safe_load(path.read_text())  # safe_load: policy files are untrusted input
    return parse_policy(data, source=str(path), extra_entities=extra_entities)


def load_preset(name: str, *, extra_entities: Iterable[str] = ()) -> Policy:
    """Load a policy shipped with the package: ngo-default, strict, dev,
    personal, or a draft regulation pack (dpdp, gdpr, hipaa-lite)."""
    ref = importlib.resources.files("virelia.policies").joinpath(f"{name}.yaml")
    try:
        text = ref.read_text()
    except FileNotFoundError:
        available = sorted(
            p.name.removesuffix(".yaml")
            for p in importlib.resources.files("virelia.policies").iterdir()
            if p.name.endswith(".yaml")
        )
        raise PolicyError(f"unknown preset {name!r}; available: {available}") from None
    data = yaml.safe_load(text)
    return parse_policy(data, source=f"preset:{name}", extra_entities=extra_entities)
