PYTHON ?= python3.12
VENV := .venv
BIN := $(VENV)/bin
SPLIT ?= dev
PREDICTOR ?= triage.baseline:predict

.PHONY: setup test lint eval

setup:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

test:
	$(BIN)/pytest

lint:
	$(BIN)/ruff check src tests

eval:
	$(BIN)/python eval/run_eval.py --split $(SPLIT) --predictor $(PREDICTOR)
