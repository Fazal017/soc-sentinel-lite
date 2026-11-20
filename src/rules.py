"""Sigma-like rule loading (stdlib only — no PyYAML required).

Rules live in ``rules/*.yaml`` in a deliberately small subset of YAML:
top-level ``key: value`` pairs, plus indented ``key: value`` pairs under
``mitre:``. Example::

    id: R001
    name: SSH Brute Force
    severity: high
    mitre:
      tactic: Credential Access
      technique: T1110.001

The detection *logic* for each rule id lives in :mod:`src.detector`;
this module only loads the rule metadata (name, description, MITRE
mapping, severity, thresholds) so analysts can tune a rule without
touching Python.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Rule:
    id: str
    name: str
    description: str = ""
    severity: str = "medium"          # low | medium | high | critical
    threshold: int = 5
    window_minutes: int = 5
    mitre_tactic: str = ""
    mitre_technique: str = ""
    mitre_name: str = ""
    enabled: bool = True

    # Severity -> base risk score (0-100 scale, before count bonus).
    BASE_SCORE = {"low": 25, "medium": 50, "high": 75, "critical": 90}

    @property
    def base_score(self) -> int:
        return self.BASE_SCORE.get(self.severity.lower(), 50)

    def risk_score(self, count: int) -> int:
        """Score grows with the observed count, capped at 100."""
        bonus = min(10, max(0, (count - self.threshold)) * 2)
        return min(100, self.base_score + bonus)


def _parse_simple_yaml(text: str) -> dict:
    """Parse the small YAML subset used by rules/*.yaml.

    Supports ``key: value``, ``key:`` + indented ``subkey: value``,
    booleans, ints and ``#`` comments. Anything more complex raises
    ValueError so a malformed rule fails loudly instead of silently.
    """
    root: dict = {}
    current: dict | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        key, sep, value = line.strip().partition(":")
        if not sep:
            raise ValueError(f"Bad rule line (expected 'key: value'): {raw!r}")
        key, value = key.strip(), value.strip()
        if indent == 0:
            if value == "":
                current = {}
                root[key] = current
            else:
                root[key] = _coerce(value)
                current = None
        elif indent in (2, 4) and current is not None:
            current[key] = _coerce(value)
        else:
            raise ValueError(f"Bad indentation in rule line: {raw!r}")
    return root


def _coerce(value: str):
    if value.lower() in ("true", "yes"):
        return True
    if value.lower() in ("false", "no"):
        return False
    try:
        return int(value)
    except ValueError:
        return value.strip("\"'")


def load_rules(rules_dir: str) -> list[Rule]:
    """Load every ``*.yaml`` / ``*.yml`` file in *rules_dir*, sorted by id."""
    rules: list[Rule] = []
    if not os.path.isdir(rules_dir):
        raise FileNotFoundError(f"Rules directory not found: {rules_dir}")
    for fname in sorted(os.listdir(rules_dir)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(rules_dir, fname), encoding="utf-8") as fh:
            data = _parse_simple_yaml(fh.read())
        mitre = data.get("mitre") or {}
        if not isinstance(mitre, dict):
            mitre = {}
        rules.append(Rule(
            id=str(data["id"]),
            name=str(data.get("name", data["id"])),
            description=str(data.get("description", "")),
            severity=str(data.get("severity", "medium")),
            threshold=int(data.get("threshold", 5)),
            window_minutes=int(data.get("window_minutes", 5)),
            mitre_tactic=str(mitre.get("tactic", "")),
            mitre_technique=str(mitre.get("technique", "")),
            mitre_name=str(mitre.get("name", "")),
            enabled=bool(data.get("enabled", True)),
        ))
    rules.sort(key=lambda r: r.id)
    return [r for r in rules if r.enabled]


def get_rule(rules: list[Rule], rule_id: str) -> Rule | None:
    return next((r for r in rules if r.id == rule_id), None)
