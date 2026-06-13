"""
Attacker cost tracker · tiktoken o200k_base.

Spec · docs/technical-paper.html §7:
  - tokenizer: tiktoken o200k_base (exact GPT-4o, lower-bound Llama)
  - track cumulative tokens per session
  - fed either by Ghost Shell (push) or by local encoding
"""
from __future__ import annotations


class AttackerCostTracker:
    """Tracks cumulative tokens per session."""

    def __init__(self) -> None:
        self._sessions: dict[str, int] = {}
        self.canary_hits = 0
        
        # Check whether tiktoken is available
        try:
            import tiktoken
            self._encoding = tiktoken.get_encoding("o200k_base")
            self._has_tiktoken = True
        except Exception:
            self._has_tiktoken = False

    def add(self, session_id: str, tokens: int) -> None:
        """Add tokens burned to a specific session."""
        if session_id not in self._sessions:
            self._sessions[session_id] = 0
        self._sessions[session_id] += tokens

    def estimate_tokens(self, text: str) -> int:
        """Estimate tokens for a given text using tiktoken or char fallback."""
        if self._has_tiktoken:
            return len(self._encoding.encode(text))
        else:
            # Estimated fallback (~3.2 characters per token in code/logs)
            return max(1, int(len(text) / 3.2))

    def get(self, session_id: str) -> int:
        """Get tokens for a session."""
        return self._sessions.get(session_id, 0)

    def total_all_sessions(self) -> int:
        """Get sum of tokens from all sessions."""
        return sum(self._sessions.values())

    def session_count(self) -> int:
        """Number of tracked attacker sessions."""
        return len(self._sessions)

    def reset(self) -> None:
        """Demo reset: clears cumulative tokens and canary hits."""
        self._sessions = {}
        self.canary_hits = 0
