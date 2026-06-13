"""Sentinel Tier 0: Sigma rule matching engine (deterministic).

Loads YAML rules from sigma_rules/ at startup and matches each LogEvent
against them. Each match returns a SigmaHit carrying its `severity`. The
cascade ROUTING lives in the Sentinel (main.py), not here: only `critical`
triggers an immediate MTD escalation, the other severities feed the T1
feature vector (sigma_hits_in_window).
"""
from __future__ import annotations

from pathlib import Path

import yaml

from services.shared.models import LogEvent, SigmaHit, SigmaSeverity

_RULES_DIR = Path(__file__).parent / "sigma_rules"


class _SigmaRule:
    def __init__(self, data: dict) -> None:
        self.rule_id: str = data.get("id", "unknown")
        self.title: str = data.get("title", "")
        self.severity: SigmaSeverity = data.get("level", "medium")
        self.detection: dict = data.get("detection", {})
        self._condition: str = str(self.detection.get("condition", "")).lower()

    def _eval_selection(self, name: str, event: LogEvent) -> bool:
        selection: dict = self.detection.get(name, {})
        for field_expr, patterns in selection.items():
            # field|modifier  (e.g. path|contains, raw|contains, method)
            if "|" in field_expr:
                field_name, modifier = field_expr.split("|", 1)
            else:
                field_name, modifier = field_expr, "equals"

            raw_val = getattr(event, field_name, None)
            value: str = str(raw_val) if raw_val is not None else ""

            pattern_list = patterns if isinstance(patterns, list) else [patterns]

            if modifier == "contains":
                if not any(str(p) in value for p in pattern_list):
                    return False
            else:
                if value not in [str(p) for p in pattern_list]:
                    return False
        return True

    def match(self, event: LogEvent, idx: int) -> SigmaHit | None:
        condition = self._condition

        # Collect selection names from detection (exclude "condition" key)
        selection_names = [k for k in self.detection if k != "condition"]

        # Build a truth table for each selection
        truth: dict[str, bool] = {
            name: self._eval_selection(name, event) for name in selection_names
        }

        # AST-based boolean expression evaluator handling OR, AND, NOT, and parentheses
        tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
        token_idx = 0

        def peek():
            if token_idx < len(tokens):
                return tokens[token_idx].lower()
            return None

        def consume(expected=None):
            nonlocal token_idx
            t = peek()
            if expected and t != expected:
                raise ValueError(f"Expected {expected}, got {t}")
            token_idx += 1
            return t

        def parse_factor() -> bool:
            t = peek()
            if t == "not":
                consume("not")
                return not parse_factor()
            elif t == "(":
                consume("(")
                res = parse_expr()
                consume(")")
                return res
            elif t is not None and t not in ("and", "or", ")"):
                name = consume()
                return truth.get(name, False)
            else:
                return False

        def parse_term() -> bool:
            val = parse_factor()
            while peek() == "and":
                consume("and")
                right = parse_factor()
                val = val and right
            return val

        def parse_expr() -> bool:
            val = parse_term()
            while peek() == "or":
                consume("or")
                right = parse_term()
                val = val or right
            return val

        try:
            result = parse_expr()
        except Exception:
            # Fallback on parse failure
            result = False

        if result:
            return SigmaHit(
                rule_id=self.rule_id,
                rule_title=self.title,
                severity=self.severity,
                matched_at=event.timestamp,
                event_index=idx,
                fields_matched={
                    name: str(getattr(event, name, ""))
                    for name in ("src_ip", "path", "method")
                    if getattr(event, name, None) is not None
                },
            )
        return None


# ── Module-level rule cache ────────────────────────────────────────────────

_RULES: list[_SigmaRule] | None = None


def _load_rules() -> list[_SigmaRule]:
    rules: list[_SigmaRule] = []
    for path in sorted(_RULES_DIR.glob("*.yml")):
        try:
            with path.open(encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            rules.append(_SigmaRule(data))
        except Exception:
            pass
    return rules


def _get_rules() -> list[_SigmaRule]:
    global _RULES
    if _RULES is None:
        _RULES = _load_rules()
    return _RULES


# ── Public API ─────────────────────────────────────────────────────────────


def match_event(event: LogEvent, idx: int = 0) -> list[SigmaHit]:
    """Match one LogEvent against all loaded Sigma rules.

    Returns a (possibly empty) list of SigmaHit objects.
    O(rules × fields), always < 1 ms in practice.
    """
    hits: list[SigmaHit] = []
    for rule in _get_rules():
        hit = rule.match(event, idx)
        if hit is not None:
            hits.append(hit)
    return hits
