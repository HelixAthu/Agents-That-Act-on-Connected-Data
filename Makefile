.PHONY: up down seed probe test dev web eval reset lint format

up:
	docker compose up -d

down:
	docker compose down

seed:
	python -m seed.seed_graph

probe:
	python scripts/probe_falkordb.py

test:
	pytest -v tests

dev:
	uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

web:
	cd frontend && npm run dev

eval:
	python -m evals.run_evals

reset:
	python -m seed.seed_graph --reset

lint:
	ruff check .

format:
	ruff format .
