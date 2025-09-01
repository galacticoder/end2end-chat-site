from __future__ import annotations

import sys
from typing import Optional

import typer

from . import __version__
from .config import AppConfig, ensure_default_config, get_config_path, load_config
from .exec import execute_shell_command
from .hotkey_daemon import run_daemon
from .model import generate_command_from_nl
from .tui import prompt_for_request


app = typer.Typer(add_completion=False, help="AI terminal executor")


@app.callback()
def _version(version: Optional[bool] = typer.Option(None, "--version", callback=lambda v: print(__version__) or sys.exit(0) if v else None, is_eager=True, help="Show version and exit.")) -> None:  # noqa: E501
	return None


@app.command(help="Open the TUI prompt, generate a command, and execute it.")
def prompt() -> None:
	cfg: AppConfig = load_config()
	user_request = prompt_for_request()
	if not user_request:
		return
	try:
		command = generate_command_from_nl(user_request, cfg)
		print(f"\nCommand: {command}\n")
		code = execute_shell_command(command, cfg)
		sys.exit(code)
	except Exception as exc:  # noqa: BLE001
		print(f"Error: {exc}")
		sys.exit(1)


@app.command(help="Run the hotkey daemon to open the prompt via a global hotkey.")
def daemon() -> None:
	cfg: AppConfig = load_config()
	run_daemon(cfg)


@app.command(help="Create a default config file if none exists, and print its path.")
def init_config() -> None:
	ensure_default_config()
	print(str(get_config_path()))


if __name__ == "__main__":
	app()

