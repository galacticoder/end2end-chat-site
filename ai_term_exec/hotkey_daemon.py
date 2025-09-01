from __future__ import annotations

import shutil
import subprocess
import shlex
from typing import List

from pynput import keyboard

from .config import AppConfig, format_hotkey_for_pynput


def _candidate_terminals() -> List[List[str]]:
	return [
		["x-terminal-emulator", "-e", "bash", "-lc", "ai-term-exec prompt"],
		["gnome-terminal", "--", "bash", "-lc", "ai-term-exec prompt"],
		["konsole", "-e", "bash", "-lc", "ai-term-exec prompt"],
		["xfce4-terminal", "-e", "bash", "-lc", "ai-term-exec prompt"],
		["tilix", "-e", "bash", "-lc", "ai-term-exec prompt"],
		["xterm", "-e", "bash", "-lc", "ai-term-exec prompt"],
		["alacritty", "-e", "bash", "-lc", "ai-term-exec prompt"],
		["kitty", "-e", "bash", "-lc", "ai-term-exec prompt"],
	]


def _resolve_terminal_cmd() -> List[str]:
	for candidate in _candidate_terminals():
		if shutil.which(candidate[0]):
			return candidate
	# Fallback: try to run in background shell; may not show a new terminal
	return ["bash", "-lc", "ai-term-exec prompt"]


def run_daemon(cfg: AppConfig) -> None:
	combo = format_hotkey_for_pynput(cfg.hotkey.combo)
	terminal_cmd = _resolve_terminal_cmd() if cfg.hotkey.terminal_cmd == "auto" else shlex.split(cfg.hotkey.terminal_cmd)

	def on_activate() -> None:
		try:
			# Launch TUI in a new terminal window
			subprocess.Popen(terminal_cmd)
		except Exception as exc:  # noqa: BLE001
			print(f"Failed to launch terminal: {exc}")

	bindings = {combo: on_activate}
	print(f"Hotkey daemon running. Press {cfg.hotkey.combo} to open the AI prompt. Ctrl+C to exit.")
	with keyboard.GlobalHotKeys(bindings) as h:
		h.join()

