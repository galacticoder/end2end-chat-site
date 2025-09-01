from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from typing import Optional

from .config import AppConfig


def _resolve_shell(shell_path: str) -> str:
	if shell_path and os.path.exists(shell_path):
		return shell_path
	for candidate in [shell_path, "/bin/bash", "/usr/bin/bash", shutil.which("bash") or "bash"]:
		if candidate and isinstance(candidate, str) and os.path.exists(candidate):
			return candidate
	return "/bin/bash"


def execute_shell_command(command: str, cfg: AppConfig) -> int:
	shell_path = _resolve_shell(cfg.execution.shell)
	if cfg.execution.dry_run:
		print(f"[dry-run] {command}")
		return 0
	if cfg.execution.confirm_before_execute:
		try:
			answer = input(f"Execute command?\n\n  {command}\n\n[y/N]: ").strip().lower()
		except KeyboardInterrupt:
			print()
			return 130
		if answer not in {"y", "yes"}:
			print("Cancelled.")
			return 0
	proc = subprocess.run([shell_path, "-lc", command], check=False)
	return proc.returncode

