from __future__ import annotations

import re
from typing import Optional

import requests

from .config import AppConfig


def _build_prompt(user_request: str, cfg: AppConfig) -> str:
	base = cfg.model.prompt_template.strip()
	return f"{base}\nUser request: {user_request.strip()}\nCommand:"


def _extract_command(text: str) -> str:
	# Prefer fenced code blocks
	code_block = re.search(r"```(?:bash|sh)?\n([\s\S]*?)```", text, flags=re.IGNORECASE)
	if code_block:
		candidate = code_block.group(1).strip()
		if candidate:
			return candidate.splitlines()[0].strip()
	# Otherwise, take the first non-empty line
	for line in text.splitlines():
		line = line.strip()
		if not line:
			continue
		# Strip leading $ if present
		if line.startswith("$"):
			line = line[1:].strip()
		return line
	return text.strip()


def generate_command_from_nl(user_request: str, cfg: AppConfig) -> str:
	if cfg.model.backend.lower() != "ollama":
		raise RuntimeError(f"Unsupported model backend: {cfg.model.backend}")

	url = cfg.model.base_url.rstrip("/") + "/api/generate"
	payload = {
		"model": cfg.model.model,
		"prompt": _build_prompt(user_request, cfg),
		"stream": False,
		"options": {"temperature": cfg.model.temperature},
	}
	resp = requests.post(url, json=payload, timeout=120)
	resp.raise_for_status()
	data = resp.json()
	text = data.get("response", "").strip()
	if not text:
		raise RuntimeError("Model returned empty response")
	return _extract_command(text)

