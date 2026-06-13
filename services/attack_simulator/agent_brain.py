"""
Agent Brain: real LLM brain for the AI_AGENT level.

Implements a ReAct loop (Thought, Action, Observation) driven by an external
LLM through the OVH AI Endpoints API (OpenAI-compatible).

The LLM receives the observation history and generates the next action: HTTP
method, path, optional body, and its explicit reasoning.

No scripted fallback: without an endpoint and LLM key, the agent does not run.
We refuse outright rather than simulate an AI attack with a deterministic
script (data integrity: a fake agent would skew the metrics).
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx


# ─── System prompt ─────────────────────────────────────────────────────────

ATTACKER_SYSTEM = """\
You are an autonomous red-team AI security agent performing a controlled penetration test.
Your goal: systematically discover credentials, configuration files, API endpoints, and \
sensitive data on the target web application.

At each step you receive the current HTTP observation. You must analyze it and decide \
your next action.

Respond ONLY with valid JSON in this exact format:
{
  "thought": "<your reasoning: what did you find? what does it mean? what should you try next?>",
  "action": {
    "method": "GET",
    "path": "/path/to/probe",
    "body": null
  }
}

For POST requests, set body to a JSON object. For GET requests, set body to null.

Strategy guidelines:
- Start with common sensitive endpoints: /.env, /.aws/credentials, /notice_to_admins.txt
- Follow up on credentials and IPs you find in responses
- If you discover instructions in a document, follow them precisely
- Probe API endpoints you find referenced in responses
- Try path variations if a path returns 404
- Maintain focus: don't repeat paths unnecessarily
- Be methodical — document your reasoning clearly in 'thought'

Only output the JSON object. No prose, no code blocks, no explanation outside the JSON.
"""

# ─── Per-turn user prompt ──────────────────────────────────────────────────

OBSERVATION_TEMPLATE = """\
Step {step} — HTTP Observation:
  URL: {method} {path}
  Status: {status}
  Response size: {size} bytes
  Response body (truncated to 500 chars):
{body_snippet}

Memory — key findings so far:
{memory_summary}

What is your next action?
"""


class AttackAction:
    """Action decided by the LLM brain."""

    def __init__(self, method: str, path: str, body: dict | None = None, thought: str = "") -> None:
        self.method = method.upper()
        self.path = path
        self.body = body
        self.thought = thought


class AgentBrain:
    """
    Real LLM agent brain via OVH AI Endpoints (OpenAI-compatible).

    Usage:
        brain = AgentBrain(base_url="...", api_key="...", model="...")
        if brain.enabled:
            action = await brain.next_action(observation)
    """

    def __init__(self, *, base_url: str, api_key: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        # `enabled` requires a COMPLETE endpoint: key + URL with an http(s):// scheme.
        # Without a scheme, every httpx call would raise UnsupportedProtocol in a loop, so
        # we block UPFRONT (enabled=False) rather than spam errors.
        _has_scheme = self.base_url.startswith(("http://", "https://"))
        self.enabled = bool(self.base_url and self.api_key and _has_scheme)
        if not self.enabled:
            # We never simulate a scripted attack: we say plainly why it is unavailable.
            if self.base_url and self.api_key and not _has_scheme:
                reason = (f"AI_ENDPOINTS_BASE_URL invalide : doit commencer par http:// ou https:// "
                          f"(reçu : {self.base_url!r}).")
            else:
                reason = "AI_ENDPOINTS_BASE_URL + AI_ENDPOINTS_API_KEY requis."
            print(
                f"\033[1;31m[AgentBrain] ✗ Agent IA indisponible : {reason} "
                "Aucune attaque scriptée de repli — configure un endpoint LLM "
                "(compatible OpenAI) pour lancer une vraie attaque ReAct.\033[0m",
                flush=True,
            )
        self._history: list[dict[str, Any]] = []   # observation memory
        self._findings: list[str] = []              # keys / secrets found
        self._step = 0
        # REAL LLM usage (the `usage` field returned by the OVH API): the attacker's true
        # cost when the attack is SELF-triggered (we drive the OVH model ourselves).
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.total_tokens = 0
        self.calls = 0
        self.last_usage: dict[str, int] | None = None   # usage of the last call (delta to report)

    # ── Public interface ────────────────────────────────────────────────────

    async def next_action(
        self,
        method: str,
        path: str,
        status: int,
        body: str,
    ) -> AttackAction | None:
        """
        Take an HTTP observation and generate the next action via the LLM.

        Returns None if the LLM API is unavailable (no key/endpoint) or if its
        response is unusable. The agent NEVER fabricates a scripted action:
        without a real LLM there is no attack (serious project, no fake data).
        """
        self._step += 1

        # Update the key findings from the response
        self._extract_findings(body)

        observation = {
            "step": self._step,
            "method": method,
            "path": path,
            "status": status,
            "body": body[:500],
        }
        self._history.append(observation)

        if not self.enabled:
            return None

        return await self._call_llm(observation)

    def reset(self) -> None:
        """Reset the memory for a new attack session."""
        self._history.clear()
        self._findings.clear()
        self._step = 0

    # ── Finding extraction ──────────────────────────────────────────────────

    def _extract_findings(self, body: str) -> None:
        """Automatically extract credentials and hints from the body."""
        # AWS keys
        aws_key = re.search(r"(AKIA[A-Z0-9]{16})", body)
        if aws_key and aws_key.group(1) not in self._findings:
            self._findings.append(f"AWS key: {aws_key.group(1)}")

        # K8s tokens
        k8s_token = re.search(r"token:\s*([a-zA-Z0-9\-_.]{20,})", body)
        if k8s_token and f"k8s token: {k8s_token.group(1)[:20]}" not in self._findings:
            self._findings.append(f"k8s token: {k8s_token.group(1)[:20]}...")

        # Internal servers
        internals = re.findall(r"([\w.-]+\.internal[:\w/]*)", body)
        for host in internals:
            item = f"internal host: {host}"
            if item not in self._findings:
                self._findings.append(item)

        # Private IPs
        private_ips = re.findall(r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.\d+\.\d+\.\d+)\b", body)
        for ip in private_ips:
            item = f"private IP: {ip}"
            if item not in self._findings:
                self._findings.append(item)

        # PI instructions
        if "IMPORTANT" in body or "acknowledge" in body.lower():
            item = "PI canary: admin acknowledgment required"
            if item not in self._findings:
                self._findings.append(item)

        # Bucket / backup paths
        buckets = re.findall(r"((?:s3|backup|archive)[^\s\"'<>]{5,50})", body)
        for b in buckets:
            item = f"backup path: {b}"
            if item not in self._findings:
                self._findings.append(item)

    # ── LLM call ────────────────────────────────────────────────────────────

    async def _call_llm(self, observation: dict) -> AttackAction:
        """Real call to the OVH AI Endpoints API."""
        self.last_usage = None   # reset to None: only set on a successful call
        memory_lines = "\n".join(f"  - {f}" for f in self._findings) if self._findings else "  (nothing significant yet)"

        user_prompt = OBSERVATION_TEMPLATE.format(
            step=observation["step"],
            method=observation["method"],
            path=observation["path"],
            status=observation["status"],
            size=len(observation.get("body", "")),
            body_snippet=observation["body"][:500] or "  (empty)",
            memory_summary=memory_lines,
        )

        messages = [
            {"role": "system", "content": ATTACKER_SYSTEM},
        ]
        # Last 4 turns of context to save tokens
        for hist in self._history[-4:]:
            messages.append({
                "role": "user",
                "content": f"[Step {hist['step']}] {hist['method']} {hist['path']} → {hist['status']}",
            })

        messages.append({"role": "user", "content": user_prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "response_format": {"type": "json_object"},
            "max_tokens": 500,   # headroom for reasoning models (otherwise budget is spent before the output)
            "temperature": 0.3,
        }

        try:
            async with httpx.AsyncClient(timeout=45.0) as client:  # big models (397B, reasoning) take over 15 s
                resp = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                # REAL usage returned by OVH (the `usage` field): true self-triggered attacker cost.
                usage = data.get("usage") or {}
                pt = int(usage.get("prompt_tokens", 0) or 0)
                ct = int(usage.get("completion_tokens", 0) or 0)
                if pt or ct:
                    self.prompt_tokens += pt
                    self.completion_tokens += ct
                    self.total_tokens += int(usage.get("total_tokens", pt + ct) or (pt + ct))
                    self.calls += 1
                    self.last_usage = {"prompt_tokens": pt, "completion_tokens": ct}
                # Robust extraction: REASONING models (Qwen3.5-397B, etc.) may leave
                # `content` empty (budget eaten by the reasoning) and put the output in
                # `reasoning_content`. Before: data["choices"][0]["message"]["content"] raised KeyError,
                # so a scripted fallback fired every turn (flagship under-used). Now lenient.
                choices = data.get("choices") or []
                msg = (choices[0].get("message") if choices else {}) or {}
                content = msg.get("content") or msg.get("reasoning_content") or ""
                if not content.strip():
                    raise ValueError(f"réponse LLM vide (reasoning-only) · modèle={self.model}")
                return self._parse_llm_response(content)
        except Exception as e:
            print(f"\033[33m[Brain] API error ({type(e).__name__}: {e}) — tour ignoré (aucun fallback scripté)\033[0m")
            return None

    def _parse_llm_response(self, text: str) -> AttackAction | None:
        """Parse the LLM JSON response (lenient: extracts the first {...} block if there is prose
        around it, common with reasoning models that prefix their JSON with text).

        Returns None if there is no usable action (missing path): we NEVER invent a
        fallback action, not even a default "GET /"."""
        try:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                import re as _re
                _m = _re.search(r"\{.*\}", text, _re.DOTALL)
                data = json.loads(_m.group(0)) if _m else {}
            if not isinstance(data, dict):
                return None
            action_data = data.get("action") or {}
            path = action_data.get("path")
            if not path:
                return None   # no path means no real action, so we fabricate nothing

            method = str(action_data.get("method", "GET")).upper()
            if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"):
                method = "GET"
            path = str(path)
            if not path.startswith("/"):
                path = "/" + path

            return AttackAction(method=method, path=path,
                                body=action_data.get("body"), thought=str(data.get("thought", "")))
        except Exception:
            # Unusable LLM response, so we invent NOTHING. The turn is skipped.
            return None
