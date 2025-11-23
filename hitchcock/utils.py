"""Utility functions for Hitchcock."""

from typing import Callable, Dict, List, Tuple, Union

# ANSI color codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BLUE = "\033[34m"
CYAN = "\033[36m"


def print_banner() -> None:
    """Print the Hitchcock banner."""
    banner = r""" _     _            _                      _
| |   (_)  _       | |                    | |
| |__  _ _| |_ ____| |__   ____ ___   ___ | |  _
|  _ \| (_   _) ___)  _ \ / ___) _ \ / _ \| |_/ )
| | | | | | |( (___| | | ( (__| |_| | |_| |  _ (
|_| |_|_|  \__)____)_| |_|\____)___/ \___/|_| \_)
"""
    print(banner)
    print("Welcome to Hitchcock - the Wrapto troubleshooting toolkit.")
    print("⚠️  Hitchcock is a testing toolkit. Do not use the generated keys or accounts in production.")


def clear_screen() -> None:
    """Clear the terminal screen."""
    print("\033c", end="")


def section_header(title: str) -> None:
    """Print a section header."""
    print()
    print(f"--- {title} ---")


def section_footer(message: str) -> None:
    """Print a section footer."""
    print()
    print(message)


def error(message: str) -> None:
    """Print an error message in red."""
    print(f"{RED}[error]{RESET} {message}")


def warn(message: str) -> None:
    """Print a warning message in yellow."""
    print(f"{YELLOW}[warn]{RESET} {message}")


def info(message: str) -> None:
    """Print an info message in blue."""
    print(f"{BLUE}[info]{RESET} {message}")


def success(message: str) -> None:
    """Print a success message in green."""
    print(f"{GREEN}[success]{RESET} {message}")


def result(message: str) -> None:
    """Print a result message in cyan."""
    print(f"{CYAN}[result]{RESET} {message}")


def bold(message: str) -> str:
    """Return a bold formatted message."""
    return f"{BOLD}{message}{RESET}"


def bold_yellow(message: str) -> str:
    """Return a bold yellow formatted message."""
    return f"{BOLD}{YELLOW}{message}{RESET}"


def bold_red(message: str) -> str:
    """Return a bold red formatted message."""
    return f"{BOLD}{RED}{message}{RESET}"


def bold_green(message: str) -> str:
    """Return a bold green formatted message."""
    return f"{BOLD}{GREEN}{message}{RESET}"


def bold_cyan(message: str) -> str:
    """Return a bold cyan formatted message."""
    return f"{BOLD}{CYAN}{message}{RESET}"


def bold_blue(message: str) -> str:
    """Return a bold blue formatted message."""
    return f"{BOLD}{BLUE}{message}{RESET}"


def print_menu(
    title: str,
    items: Union[Dict[str, str], List[Tuple[str, str]]],
    item_formatter: Callable[[str], str] | None = None,
    title_formatter: Callable[[str], str] | None = None,
) -> None:
    """Print a formatted menu.

    Args:
        title: Menu title
        items: Dictionary mapping keys to labels, or list of (key, label) tuples
        item_formatter: Optional function to format menu items (default: bold)
        title_formatter: Optional function to format title (default: no formatting)
    """
    print()
    if title_formatter:
        print(title_formatter(f"=== {title} ==="))
    else:
        print(f"=== {title} ===")

    # Default formatter makes items bold
    if item_formatter is None:
        item_formatter = bold

    # Handle both dict and list inputs
    if isinstance(items, dict):
        items_list = items.items()
    else:
        items_list = items

    for key, label in items_list:
        print(f"{key}. {item_formatter(label)}")

    print()
