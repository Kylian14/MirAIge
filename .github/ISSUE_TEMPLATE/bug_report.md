---
name: Bug report
about: Something isn't working as expected
title: "[bug] "
labels: bug
---

**Describe the bug**
A clear and concise description of what the bug is.

**To reproduce**
Steps to reproduce (commands, attack level, endpoint…):

```bash
# e.g.
docker compose up --build -d
python3 -m services.attack_simulator.attack --target http://localhost:8080 --level naive-full --duration 30
```

**Expected behaviour**
What you expected to happen.

**Environment**
- OS / Docker version:
- Running offline (default) or with an LLM/cloud configured?
- Commit / version:

**Logs**
Relevant output from `docker compose logs --tail=200`.
