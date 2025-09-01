AI Terminal Executor (ai-term-exec)
===================================

Trigger a local AI model via a hotkey or command to generate and run shell commands from a minimal TUI prompt.

Features
--------

- Press a configurable hotkey (default: Ctrl+K) to open a prompt
- Type your request; the AI returns a single shell command
- Executes the command using bash
- Works with a local Ollama instance (default)
- Simple YAML config in `~/.config/ai-term-exec/config.yml`

Install
-------

1) Ensure Python 3.8+ is available.

2) Install the package (consider using pipx):

```bash
python3 -m pip install -e /workspace
```

3) Ensure Ollama is installed and running:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull llama3.1:8b-instruct
```

Usage
-----

- One-shot prompt in the current terminal:

```bash
ai-term-exec prompt
```

- Run a hotkey daemon (best effort) to open a new terminal with the prompt:

```bash
ai-term-exec daemon
```

Configuration
-------------

On first run, a default config is created at `~/.config/ai-term-exec/config.yml`.

```yaml
model:
  backend: ollama
  base_url: http://localhost:11434
  model: llama3.1:8b-instruct
  temperature: 0.2
  prompt_template: >-
    You write a single safe, non-interactive shell command that satisfies the user's request.
    Output ONLY the command, no explanations, no code fences. Use bash-compatible syntax.

hotkey:
  enabled: true
  combo: ctrl+k
  terminal_cmd: auto

execution:
  shell: /bin/bash
  confirm_before_execute: false
  dry_run: false
```

Notes
-----

- The hotkey daemon uses system-wide hooks via `pynput`. On some Wayland sessions, global hotkeys may be restricted. In that case, use the `prompt` command directly or configure your desktop to run `ai-term-exec prompt` via a custom shortcut.
- The tool never interacts with git. It only reads your config and executes local shell commands.

