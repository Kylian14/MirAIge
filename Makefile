.PHONY: help install up down logs clean diagrams demo attack rebuild test

help:
	@echo "Mir[AI]ge — Makefile targets"
	@echo "  install      Install Python deps for each service (no docker)"
	@echo "  up           Build & start the full stack (docker-compose)"
	@echo "  down         Stop the stack"
	@echo "  logs         Tail all service logs"
	@echo "  rebuild      Rebuild docker images from scratch"
	@echo "  diagrams     Regenerate PNG diagrams from SVG sources"
	@echo "  attack       Trigger the demo attack scenario against the target"
	@echo "  demo         Open the dashboard in the browser"
	@echo "  clean        Remove build artifacts + __pycache__"

install:
	@for req in services/*/requirements.txt; do \
		echo "→ Installing $$(basename $$(dirname $$req)) deps"; \
		pip install -r "$$req"; \
	done

up:
	docker compose up --build -d
	@echo "Dashboard:    http://localhost:8000"
	@echo "Sentinel:     http://localhost:8001/health"
	@echo "Orchestrator: http://localhost:8002/health"
	@echo "MCP server:   http://localhost:8003/health"

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

rebuild:
	docker compose build --no-cache

diagrams:
	@python3 scripts/render_diagrams.py

attack:
	python3 services/attack_simulator/attack.py --target http://localhost:8080 --pattern recon

demo:
	@open http://localhost:8000 || xdg-open http://localhost:8000

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
