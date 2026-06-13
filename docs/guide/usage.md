# Using the console

Day-to-day operation: signing in, reading what the console shows, launching
red-team runs, and managing users. For the underlying endpoints see the
[API reference](api.md).

## Sign in

Open `http://localhost:8000` and log in with a username and password. With no
user store configured the single account is `admin` / `DASHBOARD_PASSWORD`; with a
[`users.json`](../../users.example.json) you get named viewer / operator / admin
accounts. Your role decides what you can do (see [Roles](api.md#authentication--roles)).

## The pages

| Page | Shows | Role |
|------|-------|------|
| **Overview** | Headline attrition: attacker tokens burned, active engagements, canaries tripped, events screened. | viewer |
| **Detection** | The three-tier cascade: how many events each tier (T0/T1/T2) eliminated or flagged. | viewer |
| **Engagements** | Live incidents: each rerouted attacker, its decoy persona/session, target and expiry. Click a row for forensics. | viewer |
| **Red team** | Launch and watch calibrated attacks. | operator |
| **Users** | Add/remove accounts, change roles, reset passwords. | admin |

The pages update in real time off a single push stream, with no manual refresh.

## Launch an attack

**From the console** (Red team page, operator role): pick a level, a duration,
and Launch. Running runs show progress and a Stop button. Each launch spoofs a
fresh source IP, so it lands as its own engagement in Detection and Engagements.

**From the CLI / a shell**, against the demo portal:

```bash
python3 -m services.attack_simulator.attack \
  --target http://localhost:8090 --level naive-full --duration 120
```

The levels are calibrated against the detection cascade:

| Level | Calibrated against |
|-------|--------------------|
| `noisy` | T0: instant Sigma match (scanner UA, `/.env`, `/.aws`…) |
| `evasive` | T1: fixed UA, paced timing, 4xx bursts |
| `stealth` | T2: high UA rotation, slow, encoded LFI |
| `ai-agent` | a real ReAct LLM brain (needs `--ai-endpoint/--ai-key`; else scripted) |
| `apt` | the honest limit: ultra-patient, multi-IP; may stay under the radar |
| `naive-full` / `hardened-agent` / `apt-bypass` | end-to-end scenarios through the whole Ghost Shell |

## Read the attrition

The point of Mir[AI]ge is the **asymmetry**: a decoy session usually costs the
attacker many times more compute than it costs the defender. `mirage_metrics`
tracks attacker tokens (tiktoken) against defender energy and surfaces it on the
Overview page and at `GET /api/v1/metrics`.

## Manage users (admin)

With a file-backed store (`MIRAIGE_USERS_FILE`), the Users page lets an admin add
accounts, change roles, and reset passwords. The last admin can't be demoted or
deleted, and you can't delete your own account. Generate a password hash for the
file directly:

```bash
python -m services.api.auth hash 'the-password'
```

## Reset

`POST /api/v1/admin/reset` (operator) clears engagements and detection state
across all agents, which is handy between demos.
