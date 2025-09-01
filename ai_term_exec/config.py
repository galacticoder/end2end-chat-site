from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


DEFAULT_CONFIG_DIR_NAME = "ai-term-exec"
DEFAULT_CONFIG_FILE_NAME = "config.yml"


@dataclass
class ModelConfig:
	backend: str = "ollama"
	base_url: str = "http://localhost:11434"
	model: str = "llama3.1:8b-instruct"
	temperature: float = 0.2
	prompt_template: str = (
		"You write a single safe, non-interactive shell command that satisfies the user's request. "
		"Output ONLY the command, no explanations, no code fences. Use bash-compatible syntax."
	)


@dataclass
class HotkeyConfig:
	enabled: bool = True
	combo: str = "ctrl+k"
	terminal_cmd: str = "auto"


@dataclass
class ExecutionConfig:
	shell: str = "/bin/bash"
	confirm_before_execute: bool = False
	dry_run: bool = False


@dataclass
class AppConfig:
	model: ModelConfig
	hotkey: HotkeyConfig
	execution: ExecutionConfig


def get_config_dir() -> Path:
	xdg = os.environ.get("XDG_CONFIG_HOME")
	if xdg:
		return Path(xdg).expanduser() / DEFAULT_CONFIG_DIR_NAME
	return Path.home() / ".config" / DEFAULT_CONFIG_DIR_NAME


def get_config_path() -> Path:
	return get_config_dir() / DEFAULT_CONFIG_FILE_NAME


def ensure_default_config() -> Path:
	config_path = get_config_path()
	config_dir = config_path.parent
	config_dir.mkdir(parents=True, exist_ok=True)
	if not config_path.exists():
		default = {
			"model": {
				"backend": "ollama",
				"base_url": "http://localhost:11434",
				"model": "llama3.1:8b-instruct",
				"temperature": 0.2,
				"prompt_template": (
					"You write a single safe, non-interactive shell command that satisfies the user's request. "
					"Output ONLY the command, no explanations, no code fences. Use bash-compatible syntax."
				),
			},
			"hotkey": {
				"enabled": True,
				"combo": "ctrl+k",
				"terminal_cmd": "auto",
			},
			"execution": {
				"shell": "/bin/bash",
				"confirm_before_execute": False,
				"dry_run": False,
			},
		}
		config_path.write_text(yaml.safe_dump(default, sort_keys=False))
	return config_path


def _merge_dict(defaults: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
	merged: Dict[str, Any] = dict(defaults)
	for key, value in overrides.items():
		if (
			key in merged
			and isinstance(merged[key], dict)
			and isinstance(value, dict)
		):
			merged[key] = _merge_dict(merged[key], value)
		else:
			merged[key] = value
	return merged


def load_config() -> AppConfig:
	config_path = ensure_default_config()
	raw = yaml.safe_load(config_path.read_text()) or {}

	default_raw = {
		"model": ModelConfig().__dict__,
		"hotkey": HotkeyConfig().__dict__,
		"execution": ExecutionConfig().__dict__,
	}
	merged = _merge_dict(default_raw, raw)

	model = ModelConfig(**merged["model"])  # type: ignore[arg-type]
	hotkey = HotkeyConfig(**merged["hotkey"])  # type: ignore[arg-type]
	execution = ExecutionConfig(**merged["execution"])  # type: ignore[arg-type]
	return AppConfig(model=model, hotkey=hotkey, execution=execution)


def format_hotkey_for_pynput(combo: str) -> str:
	parts = [p.strip().lower() for p in combo.replace("+", " ").replace("-", " ").split() if p.strip()]
	if not parts:
		return "<ctrl>+k"
	mods = []
	key = None
	for p in parts:
		if p in {"ctrl", "control"}:
			mods.append("<ctrl>")
		elif p in {"alt", "option"}:
			mods.append("<alt>")
		elif p in {"shift"}:
			mods.append("<shift>")
		elif p in {"cmd", "super", "meta", "win"}:
			mods.append("<cmd>")
		else:
			key = p
	if key is None:
		key = "k"
	return "+".join(mods + [key])

