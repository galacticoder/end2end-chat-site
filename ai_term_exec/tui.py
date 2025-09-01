from __future__ import annotations

from typing import Optional

from prompt_toolkit import prompt
from prompt_toolkit.styles import Style


PLACEHOLDER_TEXT = "Enter prompt"


def prompt_for_request() -> Optional[str]:
	style = Style.from_dict({
		"placeholder": "ansigray",
	})
	try:
		text = prompt(
			"AI> ",
			placeholder=PLACEHOLDER_TEXT,
			style=style,
		)
		request = text.strip()
		return request if request else None
	except (KeyboardInterrupt, EOFError):
		print()
		return None

