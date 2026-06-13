<!-- Thanks for contributing to Mir[AI]ge! -->

## What & why

<!-- What does this PR change, and what problem does it solve? -->

## Type

- [ ] Bug fix
- [ ] New / improved compute-wasting mechanism
- [ ] Detection (Sentinel) change
- [ ] Docs / website
- [ ] Other

## Checklist

- [ ] The stack still starts offline: `docker compose up --build -d` (no cloud creds)
- [ ] Health checks pass on ports 8001–8004, 8080, 8090
- [ ] If I touched a mechanism, it is tracked and visible in the dashboard
- [ ] No real secrets committed (`.env` stays git-ignored)
- [ ] This change is for **defensive** use only
